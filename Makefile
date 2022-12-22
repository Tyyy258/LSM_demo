obj-m:=lsm_demo.o
LOCAL_CFLAGS += -Wno-error=incompatible-pointer-types
PWD:= $(shell pwd)
KERNELDIR:= /lib/modules/$(shell uname -r)/build
EXTRA_CFLAGS= -O2
CONFIG_MODULE_SIG=n

all:
	make -C $(KERNELDIR)  M=$(PWD) modules 
clean:
	make -C $(KERNELDIR) M=$(PWD) clean

