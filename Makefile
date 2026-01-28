builddir=.
top_srcdir=../../../usr/share/apache/webroot
top_builddir=../../../usr/share/apache/webroot

SRC = oidfed_wrap_loader.c oidfed_config.c oidfed_req_handler.c
OBJ = ${SRC:%.c=%.lo}
SLO = ${SRC:.c=.slo}

include ${top_srcdir}/build/special.mk
include deps.mk

INCLUDES = -I deps/oidfed_wrap/lib/include -I src
LIBS = ${OBJ}

mod_oidfed.slo: oidfed_config.h oidfed_req_handler.h oidfed_wrap_loader.h
oidfed_config.slo: oidfed_config.h
oidfed_req_handler.slo: oidfed_config.h oidfed_wrap_loader.h oidfed_req_handler.h
oidfed_wrap_loader.slo: oidfed_config.h oidfed_wrap_loader.h oidfed_wrap_loader.gen.h oidfed_wrap_loader.gen.c

oidfed_wrap_loader.gen.c oidfed_wrap_loader.gen.h: make-loader.pl lib_builds
	exec perl make-loader.pl deps/oidfed_wrap/lib/include/oidfed_wrap_lib.h

APACHECTL=apachectl

all: lib_builds local-shared-build

local-shared-build: lib_builds

install: install-modules-yes

clean: lib_cleans
	-exec rm -f *.o mod_oidfed.lo mod_oidfed.slo mod_oidfed.la

test: reload
	lynx -mime_header http://localhost/oidfed

reload: install restart

start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

