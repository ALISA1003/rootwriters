obj-m += rootwriters.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

ccflags-y += -Wall -Wextra

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean