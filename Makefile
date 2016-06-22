include ../../build/Makefile.include

all::
	$(MAKE) -C $(KERNELDIR) M=$(PWD)
clean::
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
install:
	$(MAKE) INSTALL_MOD_DIR=iox -C $(KERNELDIR) M=$(PWD) modules_install
	install -m 755 -d $(DESTDIR)/sys
	cp /lib/modules/`uname -r`/iox/tcpproxy.ko $(DESTDIR)/sys
