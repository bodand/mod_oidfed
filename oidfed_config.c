#include <assert.h>

#include <httpd/httpd.h>
#include <http_log.h>
#include <apr_strings.h>

#include <oidfed_config.h>

static void
config_filter_append(server_rec* sv,
                     struct oidfed_config* cfg,
                     const struct oidfed_filter_config* filter_cfg,
                     struct oidfed_collection_filter* filter) {
    assert(cfg != NULL);
    assert(filter_cfg != NULL);
    assert(filter != NULL);

    uintptr_t filter_handle = 0;
    if (strcmp(filter_cfg->type, "op") == CMP_EQ)
        filter_handle = OIFMayLoad_oidfedEntityCollectionFilterOPs_server(sv);
    if (strcmp(filter_cfg->type, "explicit") == CMP_EQ)
        filter_handle = OIFMayLoad_oidfedEntityCollectionFilterOPSupportsExplicitRegistration_server(sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz);
    if (strcmp(filter_cfg->type, "auto") == CMP_EQ)
        filter_handle = OIFMayLoad_oidfedEntityCollectionFilterOPSupportsAutomaticRegistration_server(sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz);
    if (strcmp(filter_cfg->type, "grants") == CMP_EQ)
        filter_handle = OIFMayLoad_oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes_server(sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz,
            filter_cfg->arguments,
            filter_cfg->arguments_sz);
    if (strcmp(filter_cfg->type, "scopes") == CMP_EQ)
        filter_handle = OIFMayLoad_oidfedEntityCollectionFilterOPSupportedScopesIncludes_server(sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz,
            filter_cfg->arguments,
            filter_cfg->arguments_sz);

    assert(filter_handle > 0 && "unknown filter config type");
    OIFMayLoad_oidfedCollectionFilterAppend_server(sv, filter, filter_handle);
}

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
        char* err_holder = apr_palloc(parms->temp_pool, sizeof(char*) * ERROR_STR_HOLDER_SZ);
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

static bool
str_empty(const char* str) {
    return str[0] == '\0';
}

const char*
oidfed_cfg_set_entity_id(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = mconfig;
    if (!str_empty(cfg->entity_id))
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, parms->server,
                 "entity id set multiple times: was %s, now: %s", cfg->entity_id, w);

    if (strlcpy(cfg->entity_id, w, sizeof(cfg->entity_id)) >= sizeof(cfg->entity_id))
        return "entity id too long";

    return NULL;
}

const char*
oidfed_cfg_add_authority_hint(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = mconfig;
    if (cfg->authority_hints_sz == CONFIG_AUTHORITY_HINTS_MAX) return "Too many authority hints in configuration";

    cfg->authority_hints[cfg->authority_hints_sz++] = apr_pstrdup(parms->pool, w);

    return NULL;
}

static struct oidfed_filter_config**
filter_list_end(struct oidfed_config* cfg) {
    struct oidfed_filter_config** filter_list = &cfg->filters;
    while (*filter_list) filter_list = &((*filter_list)->next);
    return filter_list;
}

const char*
oidfed_add_op_filter_chain(cmd_parms* parms, void* mconfig, int argc, char* const argv[]) {
    if (argc == 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, parms->server, "ignoring empty filter chain specification");
        return NULL;
    }

    struct oidfed_config* const cfg = mconfig;
    struct oidfed_filter_config** new_filter = filter_list_end(cfg);
    if (strcmp(argv[0], "op") == CMP_EQ
        || strcmp(argv[0], "explicit") == CMP_EQ
        || strcmp(argv[0], "auto") == CMP_EQ) {
        *new_filter = apr_pcalloc(parms->pool, sizeof(struct oidfed_filter_config*));
        strcpy((*new_filter)->type, argv[0]);
        return NULL;
    }
    if (strcmp(argv[0], "grants") == CMP_EQ
        || strcmp(argv[0], "scopes") == CMP_EQ) {
        *new_filter = apr_pcalloc(parms->pool, sizeof(struct oidfed_filter_config*));
        strcpy((*new_filter)->type, argv[0]);
        (*new_filter)->arguments_sz = argc - 1;
        (*new_filter)->arguments = apr_pcalloc(parms->pool, sizeof(char*) * (*new_filter)->arguments_sz);
        for (int i = 1; i < argc; ++i) {
            (*new_filter)->arguments[i] = apr_pstrdup(parms->pool, argv[i]);
        }
        return NULL;
    }

    return "unknown filter type: expected 'op', 'explicit', 'auto', 'grants', or 'scopes'";
}

const char*
oidfed_cfg_add_trust_anchor(cmd_parms* cmd, void* cfg, const char* entity_id) {
    struct oidfed_config* const config = cfg;
    if (config->trust_anchors_sz == CONFIG_TRUST_ANCHORS_MAX) return "Too many trust anchors in configuration";

    config->trust_anchors[config->trust_anchors_sz++] = apr_pstrdup(cmd->pool, entity_id);

    return NULL;
}

static apr_status_t
oidfed_worker_runtime_uninit(void* raw) {
    struct oidfed_worker_runtime* rt = raw;
    OIFMayLoad_oidfedCollectionFilterDestroy_server(rt->server, &rt->filter);
    OIFMayLoad_oidfedCollectorDestroy_server(rt->server, &rt->collector);
    for (size_t i = 0; i < rt->trust_anchors_sz; ++i) {
        OIFMayLoad_oidfedTrustAnchorDestroy_server(rt->server, &rt->trust_anchors[i]);
    }
    return APR_SUCCESS;
}

void
oidfed_worker_runtime_init(server_rec* sv, struct oidfed_config* config) {
    assert(config->worker_cfg.runtime == 0 && "Runtime already initialized");

    struct oidfed_worker_runtime* runtime = config->worker_cfg.runtime = apr_pcalloc(sv->process->pool,
                                                                          sizeof(struct oidfed_worker_runtime));
    apr_pool_cleanup_register(sv->process->pool, runtime, oidfed_worker_runtime_uninit, NULL);

    runtime->trust_anchors = apr_pcalloc(sv->process->pool,
                                         config->trust_anchors_sz * sizeof(struct oidfed_trust_anchor));
    for (size_t i = 0; i < config->trust_anchors_sz; ++i) {
        const char* trust_anchor_id = config->trust_anchors[i];
        runtime->trust_anchors[i] = OIFMayLoad_oidfedTrustAnchorCreate_server(sv, (char*) trust_anchor_id);
    }
    runtime->trust_anchors_sz = config->trust_anchors_sz;
    fprintf(stderr, "runtime: %zu TAs", runtime->trust_anchors_sz);

    runtime->collector = OIFMayLoad_oidfedCollectorCreateSmart_server(sv,
                                                                      runtime->trust_anchors,
                                                                      runtime->trust_anchors_sz);

    runtime->filter = OIFMayLoad_oidfedEmptyCollectionFilter_server(sv);
    for (const struct oidfed_filter_config* it = config->filters;
         it;
         it = it->next) {
        config_filter_append(sv, config, it, &runtime->filter);
    }

    runtime->owner_pid = getpid();
}

void
oidfed_worker_config_init(struct oidfed_worker_config* cfg) {
    cfg->lazy_load_symbols = CONFIG_DEFAULT_LAZY_LOAD_SYMBOLS;
}

void
oidfed_config_init(struct oidfed_config* cfg) {
    oidfed_worker_config_init(&cfg->worker_cfg);
    strcpy(cfg->login_url, CONFIG_DEFAULT_LOGIN_PATH);
    strcpy(cfg->entity_id, CONFIG_DEFAULT_ENTITY_ID);
    strcpy(cfg->federation_signing_key_file, CONFIG_DEFAULT_FEDERATION_KEY_FILE);
    cfg->trust_anchors_sz = 0;
    cfg->authority_hints_sz = 0;
}
