#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/namei.h>
#include <linux/jiffies.h>
#include <linux/rwlock.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/limits.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aleksandr Isaev");
MODULE_DESCRIPTION("Restrict writes to root-owned files using /etc/fsc/rootwriters");
MODULE_VERSION("1.0");

#define ROOTWRITERS_CONFIG_PATH "/etc/fsc/rootwriters"
#define ROOTWRITERS_MAX_UIDS 256
#define ROOTWRITERS_MAX_CONFIG_BYTES (64 * 1024)

enum rootwriters_cfg_state {
	CFG_MISSING = 0,
	CFG_EMPTY,
	CFG_LOADED,
};

static uid_t authorized_uids[ROOTWRITERS_MAX_UIDS];
static size_t authorized_count;
static enum rootwriters_cfg_state cfg_state = CFG_MISSING;
static struct timespec64 cfg_mtime;
static loff_t cfg_size = -1;
static unsigned long next_reload_jiffies;
static DEFINE_RWLOCK(cfg_lock);

typedef ssize_t (*vfs_write_t)(struct file *file,
			       const char __user *buf,
			       size_t count,
			       loff_t *pos);
static vfs_write_t real_vfs_write;

struct ftrace_hook {
	const char *name;
	void *function;
	unsigned long address;
	struct ftrace_ops ops;
};

static struct ftrace_hook write_hook;

typedef unsigned long (*ftrace_location_t)(unsigned long ip);
static ftrace_location_t my_ftrace_location = NULL;

static bool same_mtime(const struct timespec64 *a, const struct timespec64 *b)
{
	return a->tv_sec == b->tv_sec && a->tv_nsec == b->tv_nsec;
}

static bool uid_exists_in_list(uid_t uid, uid_t *list, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (list[i] == uid)
			return true;
	}

	return false;
}

static void set_cfg_missing(void)
{
	write_lock(&cfg_lock);
	cfg_state = CFG_MISSING;
	authorized_count = 0;
	cfg_mtime.tv_sec = 0;
	cfg_mtime.tv_nsec = 0;
	cfg_size = -1;
	write_unlock(&cfg_lock);
}

static void publish_config(uid_t *uids, size_t count,
			   enum rootwriters_cfg_state new_state,
			   const struct timespec64 *mtime,
			   loff_t size)
{
	write_lock(&cfg_lock);
	authorized_count = count;
	if (count > 0)
		memcpy(authorized_uids, uids, count * sizeof(uid_t));
	cfg_state = new_state;
	cfg_mtime = *mtime;
	cfg_size = size;
	write_unlock(&cfg_lock);
}

static unsigned long lookup_symbol_address(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name,
	};
	unsigned long addr = 0;
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0)
		return 0;

	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

static void strip_comment(char *line)
{
	char *hash = strchr(line, '#');

	if (hash)
		*hash = '\0';
}

static int parse_uid_token(const char *token, uid_t *uid)
{
	unsigned int value;
	int ret;

	if (!token || !*token)
		return -EINVAL;

	ret = kstrtouint(token, 10, &value);
	if (ret)
		return ret;

	*uid = (uid_t)value;
	return 0;
}

static void reload_config_if_needed(void)
{
	struct file *file;
	struct kstat stat;
	loff_t pos = 0;
	loff_t size_to_read;
	char *buf = NULL;
	char *cursor;
	char *line;
	uid_t *parsed_uids = NULL;
	size_t parsed_count = 0;
	ssize_t bytes_read;
	int ret;

	if (time_before(jiffies, READ_ONCE(next_reload_jiffies)))
		return;

	WRITE_ONCE(next_reload_jiffies, jiffies + HZ);

	file = filp_open(ROOTWRITERS_CONFIG_PATH, O_RDONLY, 0);
	if (IS_ERR(file)) {
		set_cfg_missing();
		return;
	}

	ret = vfs_getattr(&file->f_path, &stat, STATX_MTIME | STATX_SIZE,
			  AT_STATX_SYNC_AS_STAT);
	if (ret) {
		filp_close(file, NULL);
		return;
	}

	read_lock(&cfg_lock);
	if (cfg_state != CFG_MISSING &&
	    same_mtime(&cfg_mtime, &stat.mtime) &&
	    cfg_size == stat.size) {
		read_unlock(&cfg_lock);
		filp_close(file, NULL);
		return;
	}
	read_unlock(&cfg_lock);

	/* Динамическое выделение памяти для предотвращения переполнения стека */
	parsed_uids = kmalloc_array(ROOTWRITERS_MAX_UIDS, sizeof(uid_t), GFP_KERNEL);
	if (!parsed_uids) {
		filp_close(file, NULL);
		return;
	}

	if (stat.size == 0) {
		publish_config(parsed_uids, 0, CFG_EMPTY, &stat.mtime, stat.size);
		kfree(parsed_uids);
		filp_close(file, NULL);
		pr_info("rootwriters: config exists and is empty, deny all\n");
		return;
	}

	size_to_read = stat.size;
	if (size_to_read > ROOTWRITERS_MAX_CONFIG_BYTES)
		size_to_read = ROOTWRITERS_MAX_CONFIG_BYTES;

	buf = kzalloc(size_to_read + 1, GFP_KERNEL);
	if (!buf) {
		kfree(parsed_uids);
		filp_close(file, NULL);
		return;
	}

	bytes_read = kernel_read(file, buf, size_to_read, &pos);
	filp_close(file, NULL);

	if (bytes_read < 0) {
		kfree(buf);
		kfree(parsed_uids);
		return;
	}

	buf[bytes_read] = '\0';
	cursor = buf;

	while ((line = strsep(&cursor, "\n")) != NULL) {
		char *work = line;
		char *token;
		uid_t uid;

		strip_comment(work);
		work = strim(work);

		if (!*work)
			continue;

		token = strsep(&work, " \t");
		if (!token || !*token)
			continue;

		if (parse_uid_token(token, &uid))
			continue;

		if (!uid_exists_in_list(uid, parsed_uids, parsed_count)) {
			if (parsed_count < ROOTWRITERS_MAX_UIDS)
				parsed_uids[parsed_count++] = uid;
		}
	}

	if (parsed_count == 0) {
		publish_config(parsed_uids, 0, CFG_EMPTY, &stat.mtime, stat.size);
		pr_info("rootwriters: config parsed, no valid UIDs found, deny all\n");
	} else {
		publish_config(parsed_uids, parsed_count, CFG_LOADED,
			       &stat.mtime, stat.size);
		pr_info("rootwriters: config reloaded, %zu authorized UID(s)\n",
			parsed_count);
	}

	kfree(buf);
	kfree(parsed_uids);
}

static bool current_uid_is_authorized(void)
{
	kuid_t curr_kuid = current_uid();
	uid_t current_val = __kuid_val(curr_kuid);
	size_t i;
	bool allowed = false;

	read_lock(&cfg_lock);

	switch (cfg_state) {
	case CFG_MISSING:
		allowed = true;
		break;
	case CFG_EMPTY:
		allowed = false;
		break;
	case CFG_LOADED:
		for (i = 0; i < authorized_count; i++) {
			if (authorized_uids[i] == current_val) {
				allowed = true;
				break;
			}
		}
		break;
	}

	read_unlock(&cfg_lock);
	return allowed;
}

static ssize_t rootwriters_vfs_write(struct file *file,
				     const char __user *buf,
				     size_t count,
				     loff_t *pos)
{
	struct inode *inode;

	if (!file)
		return real_vfs_write(file, buf, count, pos);

	inode = file_inode(file);
	if (!inode)
		return real_vfs_write(file, buf, count, pos);

	if (!S_ISREG(inode->i_mode))
		return real_vfs_write(file, buf, count, pos);

	if (__kuid_val(inode->i_uid) != 0)
		return real_vfs_write(file, buf, count, pos);

	reload_config_if_needed();

	if (!current_uid_is_authorized()) {
		pr_info_ratelimited("rootwriters: deny write for uid=%u to root-owned file\n",
				    __kuid_val(current_uid()));
		return -EACCES;
	}

	return real_vfs_write(file, buf, count, pos);
}

static void notrace rootwriters_ftrace_thunk(unsigned long ip,
					     unsigned long parent_ip,
					     struct ftrace_ops *ops,
					     struct ftrace_regs *fregs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	if (!within_module(parent_ip, THIS_MODULE))
		ftrace_regs_set_instruction_pointer(fregs,
						    (unsigned long)hook->function);
}

static int install_hook(struct ftrace_hook *hook)
{
	int ret;
	unsigned long ftrace_addr;

	if (!my_ftrace_location) {
		my_ftrace_location = (ftrace_location_t)lookup_symbol_address("ftrace_location");
		if (!my_ftrace_location) {
			pr_err("rootwriters: не удалось найти функцию ftrace_location\n");
			return -ENOENT;
		}
	}

	hook->address = lookup_symbol_address(hook->name);
	if (!hook->address)
		return -ENOENT;

	ftrace_addr = my_ftrace_location(hook->address);
	if (!ftrace_addr) {
		pr_err("rootwriters: ftrace_location не нашел точку для %s\n", hook->name);
		return -EINVAL;
	}

	real_vfs_write = (vfs_write_t)hook->address;

	hook->ops.func = rootwriters_ftrace_thunk;
	
	/* Используем макрос, который требует сохранение регистров только если архитектура это умеет.
	 * На многих arm64 FTRACE_OPS_FL_SAVE_REGS с IPMODIFY может возвращать -EINVAL.
	 */
#ifndef FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED
#define FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED FTRACE_OPS_FL_SAVE_REGS
#endif

	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED | FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_RECURSION_SAFE;

	ret = ftrace_set_filter_ip(&hook->ops, ftrace_addr, 0, 0);
	if (ret)
		return ret;

	ret = register_ftrace_function(&hook->ops);
	if (ret) {
		ftrace_set_filter_ip(&hook->ops, ftrace_addr, 1, 0);
		return ret;
	}

	return 0;
}

static void remove_hook(struct ftrace_hook *hook)
{
	unsigned long ftrace_addr;
	unregister_ftrace_function(&hook->ops);

	if (my_ftrace_location) {
		ftrace_addr = my_ftrace_location(hook->address);
		if (ftrace_addr)
			ftrace_set_filter_ip(&hook->ops, ftrace_addr, 1, 0);
	}
}

static int __init rootwriters_init(void)
{
	int ret;

	write_hook.name = "vfs_write";
	write_hook.function = rootwriters_vfs_write;

	set_cfg_missing();
	reload_config_if_needed();

	ret = install_hook(&write_hook);
	if (ret) {
		pr_err("rootwriters: failed to install ftrace hook, err=%d\n", ret);
		return ret;
	}

	pr_info("rootwriters: loaded\n");
	return 0;
}

static void __exit rootwriters_exit(void)
{
	remove_hook(&write_hook);
	pr_info("rootwriters: unloaded\n");
}

module_init(rootwriters_init);
module_exit(rootwriters_exit);