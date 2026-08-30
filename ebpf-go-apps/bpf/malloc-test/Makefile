ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	CC := x86_64-linux-gnu-gcc
else ifeq ($(ARCH),aarch64)
	CC := aarch64-linux-gnu-gcc
else
	$(error Unsupported architecture: $(ARCH))
endif

build: 
	rm malloc-test
	$(CC) malloc-test.c -o malloc-test
	echo "./malloc-test 10485760"