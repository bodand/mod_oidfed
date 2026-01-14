#ifndef OIDFED_CONFIG_H
#define OIDFED_CONFIG_H

#include <ap_config.h>
#include <httpd.h>
#include <http_config.h>
#include <stddef.h>

// COMPILE TIME CONFIGURATION //

#define CONFIG_TRUST_ANCHORS_MAX 100

// RUNTIME CONFIGURATION //

struct oidfed_worker_config {
    bool lazy_load_symbols;
};

struct oidfed_config {
    struct oidfed_worker_config worker_cfg;

    const char* trust_anchors[CONFIG_TRUST_ANCHORS_MAX];
    size_t trust_anchors_sz;
};

const char*
oidfed_cfg_add_trust_anchor(cmd_parms* cmd, void* cfg, const char* entity_id);

const char*
oidfed_cfg_wrap_lazy(cmd_parms* parms, void* mconfig, int on);

// APACHE //

extern module AP_MODULE_DECLARE_DATA oidfed_module;

static const command_rec oidfed_cmds[] = {
    AP_INIT_TAKE1("AddTrustAnchor", oidfed_cfg_add_trust_anchor, NULL, RSRC_CONF,
                  "Add given trust anchor to federation"),
    AP_INIT_FLAG("OidfedWrapperLazyLoadSymbols", oidfed_cfg_wrap_lazy, NULL, RSRC_CONF,
                 "Lazily load symbols when loading the wrap library"),
    {NULL}
};

#endif
