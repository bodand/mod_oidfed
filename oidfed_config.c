#include "oidfed_config.h"

const char*
oidfed_cfg_wrap_lazy(cmd_parms* parms, void* mconfig, int on) {
    struct oidfed_config* const config = mconfig;
    config->worker_cfg.lazy_load_symbols = (bool) on;
    return NULL;
}

const char* oidfed_cfg_login_url(cmd_parms* cmd, void* cfg, const char* url) {
    struct oidfed_config* const config = cfg;
    if (strlen(url) >= CONFIG_LOGIN_URL_SIZE_MAX) return "Login URL too long: max " APR_STRINGIFY(CONFIG_LOGIN_URL_SIZE_MAX) " characters";
    if (url[0] != '/') return "Login path must be absolute";

    strncpy(config->login_url, url, CONFIG_LOGIN_URL_SIZE_MAX);
    return NULL;
}

const char*
oidfed_cfg_add_trust_anchor(cmd_parms* cmd, void* cfg, const char* entity_id) {
    struct oidfed_config* const config = cfg;
    if (config->trust_anchors_sz == CONFIG_TRUST_ANCHORS_MAX) return "Too many trust anchors in configuration";

    config->trust_anchors[config->trust_anchors_sz++] = entity_id;

    return NULL;
}

