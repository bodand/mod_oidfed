#include <assert.h>

#include <sys/stat.h>
#include <unistd.h>

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
        filter_handle = oidfedEntityCollectionFilterOPs(sv);
    if (strcmp(filter_cfg->type, "explicit") == CMP_EQ)
        filter_handle = oidfedEntityCollectionFilterOPSupportsExplicitRegistration(sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz);
    if (strcmp(filter_cfg->type, "auto") == CMP_EQ)
        filter_handle = oidfedEntityCollectionFilterOPSupportsAutomaticRegistration(sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz);
    if (strcmp(filter_cfg->type, "grants") == CMP_EQ)
        filter_handle = oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes(sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz,
            filter_cfg->arguments,
            filter_cfg->arguments_sz);
    if (strcmp(filter_cfg->type, "scopes") == CMP_EQ)
        filter_handle = oidfedEntityCollectionFilterOPSupportedScopesIncludes(sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz,
            filter_cfg->arguments,
            filter_cfg->arguments_sz);

    assert(filter_handle > 0 && "unknown filter config type");
    oidfedCollectionFilterAppend(sv, filter, filter_handle);
}

const char*
oidfed_cfg_wrap_lazy(cmd_parms* parms, void* mconfig, int on) {
    struct oidfed_config* const config = ap_get_module_config(parms->server->module_config, &oidfed);
    config->worker_cfg.lazy_load_symbols = (bool) on;
    return NULL;
}

const char* oidfed_cfg_login_url(cmd_parms* parms, void* cfg, const char* url) {
    struct oidfed_config* const config = ap_get_module_config(parms->server->module_config, &oidfed);
    if (url[0] != '/') return "Login path must be absolute";

    if (strlcpy(config->login_url, url, CONFIG_LOGIN_URL_SIZE_MAX) > CONFIG_LOGIN_URL_SIZE_MAX)
        return "Login URL too long: max " APR_STRINGIFY(CONFIG_LOGIN_URL_SIZE_MAX) " characters";

    return NULL;
}

#define ERROR_STR_HOLDER_SZ 512

static const char*
validate_key_file_perms(apr_pool_t* pool, const char* key_file) {
    struct stat file_stat = {};
    const int res = stat(key_file, &file_stat);
    if (res < 0) {
        char* err_holder = apr_palloc(pool, sizeof(char*) * ERROR_STR_HOLDER_SZ * 2);
        snprintf(err_holder, ERROR_STR_HOLDER_SZ * 2, "cannot check key file '%s' permissions: %s", key_file,
                 strerror(errno));

        return err_holder;
    }

    const mode_t perms = file_stat.st_mode & 0777;
    if (perms == 0400 || perms == 0600) return NULL;

    char* err_holder = apr_palloc(pool, sizeof(char*) * ERROR_STR_HOLDER_SZ);
    snprintf(err_holder, ERROR_STR_HOLDER_SZ, "Key file '%s' must have 0400 or 0600 mode: currently has %04o",
             key_file, perms);
    return err_holder;
}

const char*
oidfed_cfg_set_fed_private_key(cmd_parms* parms, void* cfg, const char* key_file) {
    const char* err = validate_key_file_perms(parms->temp_pool, key_file);
    if (err) return err;

    struct oidfed_config* const config = ap_get_module_config(parms->server->module_config, &oidfed);
    if (strlcpy(config->federation_signing_key_file, key_file,
                sizeof(config->federation_signing_key_file)) >= sizeof(config->federation_signing_key_file))
        return "Federation signing key file path too long";

    return NULL;
}

const char*
oidfed_cfg_set_oidc_private_key(cmd_parms* parms, void* mconfig, const char* key_file) {
    const char* err = validate_key_file_perms(parms->temp_pool, key_file);
    if (err) return err;

    struct oidfed_config* const config = ap_get_module_config(parms->server->module_config, &oidfed);
    if (strlcpy(config->oidc_signing_key_file, key_file,
                sizeof(config->oidc_signing_key_file)) >= sizeof(config->oidc_signing_key_file))
        return "Federation signing key file path too long";

    return NULL;
}

const char*
oidfged_cfg_set_oidc_signalg(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
    if (strlcpy(cfg->oidc_signing_alg, w, sizeof(cfg->oidc_signing_alg)) >= sizeof(cfg->oidc_signing_alg))
        return "OIDC signature algorithm too long";

    return NULL;
}

const char*
oidfged_cfg_set_fed_signalg(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
    if (strlcpy(cfg->federation_signing_alg, w, sizeof(cfg->federation_signing_alg)) >=
        sizeof(cfg->federation_signing_alg))
        return "Federation signature algorithm too long";

    return NULL;
}

static bool
str_empty(const char* str) {
    return str[0] == '\0';
}

const char*
oidfed_cfg_set_entity_id(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
    if (!str_empty(cfg->entity_id))
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, parms->server,
                 "entity id set multiple times: was %s, now: %s", cfg->entity_id, w);

    if (strlcpy(cfg->entity_id, w, sizeof(cfg->entity_id)) >= sizeof(cfg->entity_id))
        return "entity id too long";

    return NULL;
}

const char*
oidfed_cfg_add_authority_hint(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
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

    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
    struct oidfed_filter_config** new_filter = filter_list_end(cfg);
    if (strcmp(argv[0], "op") == CMP_EQ
        || strcmp(argv[0], "explicit") == CMP_EQ
        || strcmp(argv[0], "auto") == CMP_EQ) {
        *new_filter = apr_pcalloc(parms->pool, sizeof(struct oidfed_filter_config));
        (*new_filter)->next = NULL;
        strcpy((*new_filter)->type, argv[0]);
        return NULL;
    }
    if (strcmp(argv[0], "grants") == CMP_EQ
        || strcmp(argv[0], "scopes") == CMP_EQ) {
        *new_filter = apr_pcalloc(parms->pool, sizeof(struct oidfed_filter_config));
        strcpy((*new_filter)->type, argv[0]);
        (*new_filter)->arguments_sz = argc - 1;
        (*new_filter)->arguments = apr_pcalloc(parms->pool, sizeof(char*) * (*new_filter)->arguments_sz);
        (*new_filter)->next = NULL;
        for (int i = 1; i < argc; ++i) {
            (*new_filter)->arguments[i - 1] = apr_pstrdup(parms->pool, argv[i]);
        }
        return NULL;
    }

    return "unknown filter type: expected 'op', 'explicit', 'auto', 'grants', or 'scopes'";
}

const char*
oidfed_cfg_add_trust_anchor(cmd_parms* parms, void* cfg, const char* entity_id) {
    struct oidfed_config* const config = ap_get_module_config(parms->server->module_config, &oidfed);
    if (config->trust_anchors_sz == CONFIG_TRUST_ANCHORS_MAX) return "Too many trust anchors in configuration";

    config->trust_anchors[config->trust_anchors_sz++] = apr_pstrdup(parms->pool, entity_id);

    return NULL;
}

static apr_status_t
oidfed_worker_runtime_uninit(void* raw) {
    struct oidfed_worker_runtime* rt = raw;
    oidfedCollectionFilterDestroy(rt->server, &rt->filter);
    oidfedCollectorDestroy(rt->server, &rt->collector);
    for (size_t i = 0; i < rt->trust_anchors_sz; ++i) {
        oidfedTrustAnchorDestroy(rt->server, &rt->trust_anchors[i]);
    }
    return APR_SUCCESS;
}


#define SLURP_BUF_SZ 4096

void
slurp_file(apr_pool_t* pool, const char* path, char** out_chars, size_t* out_chars_sz) {
    FILE* f = fopen(path, "r");
    if (!f) return;

    size_t alloc_sz = SLURP_BUF_SZ;
    size_t file_sz = 1; // ensure a place for \0
    char* ret = apr_pcalloc(pool, alloc_sz);
    char* data = ret;

    size_t last_read = 0;
    while ((last_read = fread(data, 1, alloc_sz - file_sz, f)) > 0) {
        file_sz += last_read;
        data += last_read;
        if (file_sz == alloc_sz) {
            char* const old_ret = ret;
            const size_t old_alloc_sz = alloc_sz;

            alloc_sz = (size_t) ((double) alloc_sz * 1.5);
            ret = apr_pcalloc(pool, alloc_sz);
            memcpy(ret, old_ret, old_alloc_sz);
            explicit_bzero(old_ret, old_alloc_sz);
            data = ret + file_sz;
        }
    }

    ret[file_sz - 1] = '\0';
    *out_chars = ret;
    *out_chars_sz = file_sz - 1;
    fclose(f);
}

void
oidfed_worker_runtime_init(server_rec* sv, struct oidfed_config* config) {
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "initiating worker: %d", getpid());
    assert(config->worker_cfg.runtime == 0 && "Runtime already initialized");

    struct oidfed_worker_runtime* runtime =
            config->worker_cfg.runtime =
            apr_pcalloc(sv->process->pool, sizeof(struct oidfed_worker_runtime));
    apr_pool_cleanup_register(sv->process->pool, runtime, oidfed_worker_runtime_uninit, NULL);

    runtime->server = sv;

    runtime->trust_anchors = apr_pcalloc(sv->process->pool,
                                         config->trust_anchors_sz * sizeof(struct oidfed_trust_anchor));
    for (size_t i = 0; i < config->trust_anchors_sz; ++i) {
        const char* trust_anchor_id = config->trust_anchors[i];
        runtime->trust_anchors[i] = oidfedTrustAnchorCreate(sv, (char*) trust_anchor_id);
    }
    runtime->trust_anchors_sz = config->trust_anchors_sz;

    runtime->collector = oidfedCollectorCreateSmart(sv,
                                                                      runtime->trust_anchors,
                                                                      runtime->trust_anchors_sz);

    runtime->filter = oidfedEmptyCollectionFilter(sv);
    for (const struct oidfed_filter_config* it = config->filters;
         it;
         it = it->next) {
        config_filter_append(sv, config, it, &runtime->filter);
    }

    int errc = 0;
    char* chars = NULL;
    size_t chars_sz = 0;
    slurp_file(sv->process->pool, config->federation_signing_key_file, &chars, &chars_sz);
    const struct oidfed_signer fed_signer = oidfedSignerCreateFromPEM(sv, chars, chars_sz, &errc);
    explicit_bzero(chars, chars_sz);
    if (errc != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv, "Failed to load federation signing key: error code %d", errc);
        return;
    }

    chars = NULL;
    chars_sz = 0;
    slurp_file(sv->process->pool, config->oidc_signing_key_file, &chars, &chars_sz);
    const struct oidfed_signer oidc_signer = oidfedSignerCreateFromPEM(sv, chars, chars_sz, &errc);
    explicit_bzero(chars, chars_sz);
    if (errc != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv, "Failed to load oidc signing key: error code %d", errc);
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "(worker:%d) finding signing algorithm for federation: %s",
                 getpid(),
                 config->federation_signing_alg);
    bool succ = false;
    runtime->federation_signing_alg = oidfedSignatureAlgorithmGet(
        sv, config->federation_signing_alg, &succ);
    if (!succ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv, "Failed to load oidc signing key: unknown signature algorithm: %s",
                     config->federation_signing_alg);
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "(worker:%d) finding signing algorithm for oidc: %s",
                 getpid(),
                 config->oidc_signing_alg);
    succ = false;
    runtime->oidc_signing_alg = oidfedSignatureAlgorithmGet(sv, config->oidc_signing_alg, &succ);
    if (!succ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv, "Failed to load oidc signing key: unknown signature algorithm: %s",
                     config->oidc_signing_alg);
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "(worker:%d) creating key storage for federation", getpid());
    runtime->federation_key_storage = oidfedSingleKeyStorageCreate(
        sv, fed_signer, runtime->federation_signing_alg);
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "(worker:%d) creating signer for federation", getpid());
    runtime->federation_signer = oidfedSingleKeyStorageAsVersatileSigner(&runtime->federation_key_storage);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "(worker:%d) creating key storage for oidc", getpid());
    runtime->oidc_key_storage = oidfedSingleKeyStorageCreate(
        sv, oidc_signer, runtime->oidc_signing_alg);
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "(worker:%d) creating signer for oidc", getpid());
    runtime->oidc_signer = oidfedSingleKeyStorageAsVersatileSigner(&runtime->oidc_key_storage);

    // After success, set the owner pid; this can act as a sanity check that we did not break things
    // in a way that made httpd give this object to another worker somehow.
    runtime->owner_pid = getpid();
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "initialized worker: %d, ready to work", getpid());
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
    strcpy(cfg->federation_signing_alg, CONFIG_DEFAULT_FED_SIGNALG);

    strcpy(cfg->oidc_signing_key_file, CONFIG_DEFAULT_OIDC_KEY_FILE);
    strcpy(cfg->oidc_signing_alg, CONFIG_DEFAULT_OIDC_SIGNALG);

    cfg->trust_anchors_sz = 0;
    cfg->authority_hints_sz = 0;
    cfg->filters = NULL;
}
