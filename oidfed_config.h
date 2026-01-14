#ifndef OIDFED_CONFIG_H
#define OIDFED_CONFIG_H

#include <ap_config.h>
#include <httpd.h>
#include <http_config.h>
#include <stddef.h>

// COMPILE TIME CONFIGURATION //

#define CONFIG_TRUST_ANCHORS_MAX 100
#define CONFIG_LOGIN_URL_SIZE_MAX 256

#define OIDFED_WELL_KNOWN_PATH "/.well-known/openid-federation"

// RUNTIME CONFIGURATION //

struct oidfed_worker_config {
    bool lazy_load_symbols;
};

struct oidfed_config {
    char login_url[CONFIG_LOGIN_URL_SIZE_MAX];

    struct oidfed_worker_config worker_cfg;

    const char* trust_anchors[CONFIG_TRUST_ANCHORS_MAX];
    size_t trust_anchors_sz;
};

const char*
oidfed_cfg_add_trust_anchor(cmd_parms* cmd, void* cfg, const char* entity_id);

const char*
oidfed_cfg_wrap_lazy(cmd_parms* parms, void* mconfig, int on);

const char*
oidfed_cfg_login_url(cmd_parms* cmd, void* cfg, const char* url);

// APACHE //

extern module AP_MODULE_DECLARE_DATA oidfed_module;

static const command_rec oidfed_cmds[] = {
    AP_INIT_TAKE1("OidfedAddTrustAnchor", oidfed_cfg_add_trust_anchor, NULL, RSRC_CONF,
                  "Add given trust anchor to federation"),
    AP_INIT_TAKE1("OidfedSetLoginPath", oidfed_cfg_login_url, NULL, RSRC_CONF,
                  "Sets the path to redirect the user to when logging in."),
    AP_INIT_FLAG("OidfedWrapperLazyLoadSymbols", oidfed_cfg_wrap_lazy, NULL, RSRC_CONF,
                 "Lazily load symbols when loading the wrap library"),
    {NULL}
};

#define CMP_EQ 0

#endif
