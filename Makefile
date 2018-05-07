obj-m= esp8266.o

all:
	make M=$(PWD) -C /usr/src/linux-headers-$$(uname -r)/ modules

clean:
	make M=$(PWD) -C /usr/src/linux-headers-$$(uname -r)/ clean
	rm -f *~

.PHONY: clean
