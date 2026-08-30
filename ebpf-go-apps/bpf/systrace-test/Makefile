ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	CC := x86_64-linux-gnu-gcc
else ifeq ($(ARCH),aarch64)
	CC := aarch64-linux-gnu-gcc
else
	$(error Unsupported architecture: $(ARCH))
endif

build: 
	rm systrace-test
	$(CC) systrace-test.c -o systrace-test