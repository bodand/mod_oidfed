
DEPENDENCIES := oidfed_wrap
lib_builds:
	@for dep in ${DEPENDENCIES}; do \
	  ${MAKE} -C "deps/$$dep" ensure; \
	done

lib_cleans:
	@for dep in ${DEPENDENCIES}; do \
	  ${MAKE} -C "deps/$$dep" clean; \
	done

