builddir=.
top_srcdir=/etc/httpd
top_builddir=/usr/lib64/httpd

SRC = oidfed_wrap_loader.c oidfed_config.c oidfed_req_handler.c
OBJ = ${SRC:%.c=%.lo}
SLO = ${SRC:.c=.slo}

include /usr/lib64/httpd/build/special.mk
include deps.mk

INCLUDES = -I deps/oidfed_wrap/lib/include -I src
LIBS = ${OBJ}

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

