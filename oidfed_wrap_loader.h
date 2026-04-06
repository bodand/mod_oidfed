#ifndef OIDFED_OIDFED_WRAP_LOADER_H
#define OIDFED_OIDFED_WRAP_LOADER_H

#include <httpd.h>

#include <oidfed_config_fwd.h>
#include <oidfed_wrap_lib.h>

apr_status_t
oidfed_worker_init(const struct oidfed_worker_config* cfg, apr_pool_t* p);

#include "oidfed_wrap_loader.gen.h"

#endif
