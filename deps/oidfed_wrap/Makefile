## Makefile to pull and build oidfed_wrap locally
#
OIDFED_WRAP_VERSION := 3d8fe1cb819b2d5e45309cd31864891204639bcd

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
