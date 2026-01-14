mod_oidfed.la: mod_oidfed.slo $(SLO)
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version mod_oidfed.lo $(OBJ)
DISTCLEAN_TARGETS = modules.mk
shared =  mod_oidfed.la
