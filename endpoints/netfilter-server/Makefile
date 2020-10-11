all: kernel user

user: cfg_lbbps

obj-m += lbbps_main.o
kernel:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	 rm -f *.o
