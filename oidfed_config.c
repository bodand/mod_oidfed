#include "oidfed_config.h"

const char*
oidfed_cfg_wrap_lazy(cmd_parms* parms, void* mconfig, int on) {
    struct oidfed_config* const config = mconfig;
    config->worker_cfg.lazy_load_symbols = (bool) on;
    return NULL;
}

const char* oidfed_cfg_login_url(cmd_parms* cmd, void* cfg, const char* url) {
    struct oidfed_config* const config = cfg;
    if (url[0] != '/') return "Login path must be absolute";

    if (strlcpy(config->login_url, url, CONFIG_LOGIN_URL_SIZE_MAX) > CONFIG_LOGIN_URL_SIZE_MAX)
        return "Login URL too long: max " APR_STRINGIFY(
            CONFIG_LOGIN_URL_SIZE_MAX) " characters";

    return NULL;
}

#define ERROR_STR_HOLDER_SZ 512

const char*
oidfed_cfg_fed_singing_key(cmd_parms* parms, void* cfg, const char* key_file) {
    apr_finfo_t finfo;
    const apr_status_t res = apr_stat(&finfo, key_file, APR_FINFO_SIZE | APR_FINFO_PROT, parms->pool);
    if (res != APR_SUCCESS && res != APR_INCOMPLETE) {
        char* err_holder = apr_palloc(parms->pool, sizeof(char*) * ERROR_STR_HOLDER_SZ);
        return apr_strerror(res, err_holder, ERROR_STR_HOLDER_SZ);
    }

    if (finfo.valid & APR_FINFO_PROT) return "Key file cannot be checked for mode to be 400. Refusing using it.";
    if (finfo.protection != 0400) return "Key file must be readable only by owner (mode 400).";

    struct oidfed_config* const config = cfg;
    if (strlcpy(config->federation_signing_key_file, key_file,
                sizeof(config->federation_signing_key_file)) >= sizeof(config->federation_signing_key_file))
        return "Federation signing key file path too long";

    return NULL;
}

const char*
oidfed_cfg_add_trust_anchor(cmd_parms* cmd, void* cfg, const char* entity_id) {
    struct oidfed_config* const config = cfg;
    if (config->trust_anchors_sz == CONFIG_TRUST_ANCHORS_MAX) return "Too many trust anchors in configuration";

    config->trust_anchors[config->trust_anchors_sz++] = entity_id;

    return NULL;
}
