## Makefile to pull and build oidfed_wrap locally
#
OIDFED_WRAP_VERSION := 68c6d6c9f8cc783b7b6335a468478a09ae7a33e9

.PHONY: ensure checkout build install clean
ensure: checkout build install

checkout:
	cd src && exec git checkout ${OIDFED_WRAP_VERSION}

install: .install.time

.install.time: .build.time
	exec ${MAKE} -C src PREFIX=../lib install
	touch $@

build: .build.time

.build.time: Makefile
	exec ${MAKE} -C src build
	touch $@

clean:
	exec ${MAKE} -C src clean
	exec rm -f .*.time
