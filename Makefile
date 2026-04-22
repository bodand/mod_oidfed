CHECK_CONFIG := $(shell if [ ! -f config.mk ] || [ Makefile -nt config.mk ]; then echo "error"; fi)

ifeq ($(CHECK_CONFIG),error)
  $(error "config.mk missing or older than Makefile, rerun ./configure")
endif
include config.mk

SITE ?= /var/www/html

builddir     = .
top_srcdir   = ${apxs_exp_datadir}
top_builddir = ${apxs_exp_datadir}

SRC = oidfed_wrap_loader.c oidfed_config.c oidfed_req_handler.c utils.c
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
utils.slo: utils.h

oidfed_wrap_loader.gen.c oidfed_wrap_loader.gen.h: make-loader.pl deps/oidfed_wrap/lib/include/oidfed_wrap_lib.h
	exec perl make-loader.pl deps/oidfed_wrap/lib/include/oidfed_wrap_lib.h

APACHECTL=apachectl

all: lib_builds local-shared-build

local-shared-build: lib_builds

install: install-modules-yes ${apxs_exp_libdir}/oidfed_wrap.so
	@exec echo "===================== CSS installation ========================"
	@exec echo "You need to ensure you copy oidfed.css to your site's root, or"
	@exec echo "provide your own version for styling."
	@exec echo "To install the built-in version automatically, run: "
	@exec echo ""
	@exec echo "  make css SITE=<your site's root dir>"
	@exec echo ""
	@exec echo "If SITE is not set, it defaults to /var/www/html"
	@exec echo "==============================================================="

${apxs_exp_libdir}/oidfed_wrap.so: deps/oidfed_wrap/lib/lib/liboidfed_wrap.so
	exec install -m644 deps/oidfed_wrap/lib/lib/liboidfed_wrap.so $@

css: ${SITE}/oidfed.css

${SITE}/oidfed.css: oidfed.css
	@exec install -m644 oidfed.css $@

clean: lib_cleans
	-exec rm -f *.o ${OBJ} ${SLO} mod_oidfed.slo mod_oidfed.la

test: reload
	lynx -mime_header http://localhost/oidfed

reload: install restart

start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop
