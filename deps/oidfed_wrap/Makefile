## Makefile to pull and build oidfed_wrap locally
#

.PHONY: ensure checkout build install clean
ensure: build install

install: .install.time

.install.time: .build.time
	exec ${MAKE} -C src PREFIX=../lib install
	exec touch $@

build: .build.time

.build.time: Makefile
	exec ${MAKE} -C src build
	exec touch $@

clean:
	exec ${MAKE} -C src clean
	exec rm -f .*.time
