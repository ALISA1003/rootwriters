#!/usr/bin/env bash
set -euo pipefail

MODULE_NAME="rootwriters"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE_FILE="${REPO_DIR}/${MODULE_NAME}.ko"
KDIR="/lib/modules/$(uname -r)/build"
CONFIG_DIR="/etc/fsc"
CONFIG_FILE="${CONFIG_DIR}/rootwriters"
CURRENT_UID="$(id -u)"
CURRENT_USER="$(id -un)"

echo "[*] Repo: ${REPO_DIR}"
echo "[*] Kernel: $(uname -r)"
echo "[*] Arch:   $(uname -m)"

# Для ftrace-хука с перенаправлением IP (IPMODIFY) ядро должно быть
# собрано с CONFIG_DYNAMIC_FTRACE_WITH_REGS. Предупреждаем заранее.
CONFIG_GZ="/proc/config.gz"
if [ -r "${CONFIG_GZ}" ]; then
    if zcat "${CONFIG_GZ}" | grep -q '^CONFIG_DYNAMIC_FTRACE_WITH_REGS=y'; then
        echo "[*] CONFIG_DYNAMIC_FTRACE_WITH_REGS=y (OK)"
    else
        echo "[!] ВНИМАНИЕ: CONFIG_DYNAMIC_FTRACE_WITH_REGS не включен — хук может не заработать"
    fi
elif [ -r "/boot/config-$(uname -r)" ]; then
    if grep -q '^CONFIG_DYNAMIC_FTRACE_WITH_REGS=y' "/boot/config-$(uname -r)"; then
        echo "[*] CONFIG_DYNAMIC_FTRACE_WITH_REGS=y (OK)"
    else
        echo "[!] ВНИМАНИЕ: CONFIG_DYNAMIC_FTRACE_WITH_REGS не включен — хук может не заработать"
    fi
fi

if ! command -v sudo >/dev/null 2>&1; then
    echo "[!] sudo not found"
    exit 1
fi

sudo -v

if [ ! -d "${KDIR}" ]; then
    echo "[*] Kernel headers not found, trying to install dependencies..."
    sudo apt update
    sudo apt install -y build-essential linux-headers-$(uname -r) kmod
fi

if [ ! -d "${KDIR}" ]; then
    echo "[!] Kernel build directory still missing: ${KDIR}"
    exit 1
fi

echo "[*] Building module..."
make -C "${REPO_DIR}" clean
make -C "${REPO_DIR}"

if [ ! -f "${MODULE_FILE}" ]; then
    echo "[!] Build finished, but ${MODULE_FILE} not found"
    exit 1
fi

echo "[*] Preparing config directory..."
sudo install -d -m 755 "${CONFIG_DIR}"

if [ ! -f "${CONFIG_FILE}" ]; then
    echo "[*] Creating default ${CONFIG_FILE}"
    sudo tee "${CONFIG_FILE}" >/dev/null <<EOF
# Authorized users for writes to root-owned files
# One UID per line; extra fields are ignored

0 root
${CURRENT_UID} ${CURRENT_USER}
EOF
else
    echo "[*] Keeping existing ${CONFIG_FILE}"
fi

if lsmod | awk '{print $1}' | grep -qx "${MODULE_NAME}"; then
    echo "[*] Removing previous module instance..."
    sudo rmmod "${MODULE_NAME}"
fi

echo "[*] Loading module..."
sudo insmod "${MODULE_FILE}"

echo "[*] Module loaded:"
lsmod | grep "^${MODULE_NAME}[[:space:]]" || true

echo "[*] Recent kernel log:"
sudo dmesg | tail -n 20 | grep -i "${MODULE_NAME}" || true

echo "[+] Installation completed"