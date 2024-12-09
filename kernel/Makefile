MODULE_NAME = sniffer
MODULE_SRCS := src/hooks.o main.o

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := $(MODULE_SRCS) 

EXTRA_CFLAGS += -I$(shell pwd)/headers

KDIR := /usr/src/linux-headers-$(shell uname -r)

all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules
	rm *.mod.c .*.cmd *.o *.symvers src/.*.cmd src/*.o

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) clean
	rm -f *.o