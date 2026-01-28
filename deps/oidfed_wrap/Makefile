## Makefile to pull and build oidfed_wrap locally
#
OIDFED_WRAP_VERSION := eb2434346e71300f8294de58d9becfb219f39c64

.PHONY: ensure checkout build install clean
ensure: checkout build install

checkout:
	cd src && exec git checkout ${OIDFED_WRAP_VERSION}

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
