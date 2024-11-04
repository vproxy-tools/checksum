.DEFAULT_GOAL = all

OS := $(shell uname)

.PHONY: clean
clean:
	rm -f libcsum.so
	rm -f libcsum.dylib
	rm -f csum.dll

.PHONY: all
all: libcsum

.PHONY: libcsum
libcsum:
ifeq ($(OS),Darwin)
	gcc -O2 -g -o libcsum.dylib -fPIC -shared vproxy_checksum.c
else ifeq ($(OS),Linux)
	gcc -O2 -g -o libcsum.so -fPIC -shared vproxy_checksum.c
else
	gcc -O2 -g -o csum.dll -fPIC -shared vproxy_checksum.c
endif
