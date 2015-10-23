
BASEDIR= /home/kkr/s/9x/92107/Prog/PPC/
CC=/opt/crosstool-ng-powerpc/bin/powerpc-e500v2-linux-gnuspe-gcc
SYSROOT=$(BASEDIR)/git/buildroot/output/staging
TARGET=test

default: $(TARGET)


$(TARGET) : crypt.c
	$(CC) $^ -o $@ -lgcrypt -lgpg-error --sysroot=$(SYSROOT) -I$(SYSROOT)/usr/include/

upload:
	scp test root@192.168.32.32:

run: upload
	ssh root@192.168.32.32 /root/test


clean:
	rm -rf $(TARGET) crypt.o
