#include <assert.h>

#include <unistd.h>
#include <sys/stat.h>

#include <httpd.h>
#include <http_log.h>

#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_thread_mutex.h>
#include <oidfed_config.h>

struct in_memory_storage_impl {
    apr_hash_t* hash;
    apr_thread_mutex_t* mutex;
};

static void
in_memory_set(const struct oidfed_session_storage* storage,
              const struct oidfed_session* session) {
    const struct in_memory_storage_impl* impl = storage->impl;
    apr_thread_mutex_lock(impl->mutex);
    apr_hash_set(impl->hash, session->sid, APR_HASH_KEY_STRING, session);
    apr_thread_mutex_unlock(impl->mutex);
}

static struct oidfed_session*
in_memory_get(const struct oidfed_session_storage* storage,
              const char* sid) {
    const struct in_memory_storage_impl* impl = storage->impl;
    apr_thread_mutex_lock(impl->mutex);
    struct oidfed_session* session = apr_hash_get(impl->hash, sid, APR_HASH_KEY_STRING);
    apr_thread_mutex_unlock(impl->mutex);
    return session;
}

static void
in_memory_remove(const struct oidfed_session_storage* storage,
                 const char* sid) {
    const struct in_memory_storage_impl* impl = storage->impl;
    apr_thread_mutex_lock(impl->mutex);
    apr_hash_set(impl->hash, sid, APR_HASH_KEY_STRING, NULL);
    apr_thread_mutex_unlock(impl->mutex);
}

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
        filter_handle = oidfedEntityCollectionFilterOPSupportsExplicitRegistration(
            sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz
        );
    if (strcmp(filter_cfg->type, "auto") == CMP_EQ)
        filter_handle = oidfedEntityCollectionFilterOPSupportsAutomaticRegistration(
            sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz
        );
    if (strcmp(filter_cfg->type, "grants") == CMP_EQ)
        filter_handle = oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes(
            sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz,
            filter_cfg->arguments,
            filter_cfg->arguments_sz
        );
    if (strcmp(filter_cfg->type, "scopes") == CMP_EQ)
        filter_handle = oidfedEntityCollectionFilterOPSupportedScopesIncludes(
            sv,
            cfg->trust_anchors,
            cfg->trust_anchors_sz,
            filter_cfg->arguments,
            filter_cfg->arguments_sz
        );

    assert(filter_handle > 0 && "unknown filter config type");
    oidfedCollectionFilterAppend(sv, filter, filter_handle);
}

const char*
oidfed_cfg_wrap_lazy(cmd_parms* parms, void* mconfig, int on) {
    struct oidfed_config* const config = ap_get_module_config(parms->server->module_config, &oidfed);
    config->worker_cfg.lazy_load_symbols = (bool)on;
    return NULL;
}

const char*
oidfed_cfg_login_url(cmd_parms* parms, void* cfg, const char* url) {
    struct oidfed_config* const config = ap_get_module_config(parms->server->module_config, &oidfed);
    if (url[0] != '/') return "Login path must be absolute";

    if (strlcpy(config->login_url, url, CONFIG_LOGIN_URL_SIZE_MAX) > CONFIG_LOGIN_URL_SIZE_MAX)
        return "Login URL too long: max " APR_STRINGIFY(CONFIG_LOGIN_URL_SIZE_MAX) " characters";

    return NULL;
}

static const char*
validate_key_file_perms(apr_pool_t* pool, const char* key_file) {
    struct stat file_stat = {};
    const int res = stat(key_file, &file_stat);
    if (res < 0) {
        return apr_psprintf(
            pool,
            "cannot check key file '%s' permissions: %s", key_file,
            strerror(errno)
        );
    }

    const mode_t perms = file_stat.st_mode & 0777;
    if (perms == 0400 || perms == 0600) return NULL;

    return apr_psprintf(
        pool, "Key file '%s' must have 0400 or 0600 mode: currently has %04o",
        key_file,
        perms
    );
}

#define SAFE_COPY_CONFIG(parms, name, config_field, value) \
    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed); \
    const size_t entity_size = sizeof(cfg->config_field); \
    if (strlcpy(cfg->config_field, value, entity_size) >= entity_size) { \
        return apr_psprintf(parms->pool, \
            name ": value too long (max %zu)",\
            entity_size \
        ); \
    } \
    return NULL;

const char*
oidfed_cfg_set_entity_id(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetEntityId", entity_id, w);
}

const char*
oidfed_cfg_add_authority_hint(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
    if (cfg->authority_hints_sz == CONFIG_AUTHORITY_HINTS_MAX)
        return "Too many authority hints in configuration";

    cfg->authority_hints[cfg->authority_hints_sz++] = apr_pstrdup(parms->pool, w);

    return NULL;
}

const char*
oidfed_cfg_set_fed_private_key(cmd_parms* parms, void* cfg, const char* key_file) {
    const char* err = validate_key_file_perms(parms->temp_pool, key_file);
    if (err) return err;

    struct oidfed_config* const config = ap_get_module_config(parms->server->module_config, &oidfed);
    const size_t sign_fname_size = sizeof(config->federation_signing_key_file);
    if (strlcpy(config->federation_signing_key_file, key_file, sign_fname_size) >= sign_fname_size) {
        return apr_psprintf(
            parms->pool, "OidfedSetOidFederationSigningKey: value too long (max %lu)",
            (unsigned long)sign_fname_size - 1
        );
    }

    return NULL;
}

const char*
oidfed_cfg_set_oidc_private_key(cmd_parms* parms, void* mconfig, const char* key_file) {
    const char* err = validate_key_file_perms(parms->temp_pool, key_file);
    if (err) return err;

    SAFE_COPY_CONFIG(parms, "OidfedSetOidConnectSigningKey", oidc_signing_key_file, key_file);
}

const char*
oidfged_cfg_set_oidc_signalg(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetOidConnectSignatureAlgorithm", oidc_signing_alg, w);
}

const char*
oidfged_cfg_set_fed_signalg(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetOidFederationSignatureAlgorithm", federation_signing_alg, w);
}

static struct oidfed_filter_config**
filter_list_end(struct oidfed_config* cfg) {
    struct oidfed_filter_config** filter_list = &cfg->filters;
    while (*filter_list) filter_list = &((*filter_list)->next);
    return filter_list;
}

const char*
oidfed_cfg_add_trust_anchor(cmd_parms* parms, void* cfg, const char* entity_id) {
    struct oidfed_config* const config = ap_get_module_config(parms->server->module_config, &oidfed);
    if (config->trust_anchors_sz == CONFIG_TRUST_ANCHORS_MAX)
        return "Too many trust anchors in configuration";

    config->trust_anchors[config->trust_anchors_sz++] = apr_pstrdup(parms->pool, entity_id);

    return NULL;
}

const char*
oidfed_add_op_filter_chain(cmd_parms* parms, void* mconfig, int argc, char* const argv[]) {
    if (argc == 0) {
        ap_log_error(
            APLOG_MARK, APLOG_WARNING, 0, parms->server,
            "ignoring empty filter chain specification"
        );
        return NULL;
    }

    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
    struct oidfed_filter_config** new_filter = filter_list_end(cfg);

    const size_t type_size = sizeof((*new_filter)->type);
    if (strcmp(argv[0], "op") == CMP_EQ
        || strcmp(argv[0], "explicit") == CMP_EQ
        || strcmp(argv[0], "auto") == CMP_EQ) {
        *new_filter = apr_pcalloc(parms->pool, sizeof(struct oidfed_filter_config));
        (*new_filter)->next = NULL;

        if (strlcpy((*new_filter)->type, argv[0], type_size) >= type_size) {
            goto type_too_long;
        }

        return NULL;
    }

    if (strcmp(argv[0], "grants") == CMP_EQ
        || strcmp(argv[0], "scopes") == CMP_EQ) {
        *new_filter = apr_pcalloc(parms->pool, sizeof(struct oidfed_filter_config));
        (*new_filter)->next = NULL;

        if (strlcpy((*new_filter)->type, argv[0], type_size) >= type_size) {
            goto type_too_long;
        }

        (*new_filter)->arguments_sz = argc - 1;
        (*new_filter)->arguments = apr_pcalloc(
            parms->pool,
            sizeof(char*) * (*new_filter)->arguments_sz
        );

        for (int i = 1; i < argc; ++i) {
            (*new_filter)->arguments[i - 1] = apr_pstrdup(parms->pool, argv[i]);
        }

        return NULL;
    }

    return "unknown filter type: expected 'op', 'explicit', 'auto', 'grants', or 'scopes'";

type_too_long:
    return apr_psprintf(
        parms->pool, "OidfedAddOPFilterChain: filter type too long (max %lu)",
        type_size - 1
    );
}

const char*
oidfed_cfg_set_rp_metadata_url(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetRPMetadataURL", metadata.rp_metadata_url, w);
}

const char*
oidfed_cfg_set_rp_metadata_digest(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetRPMetadataDigest", metadata.rp_metadata_digest, w);
}

const char*
oidfed_cfg_set_rp_metadata_digest_alg(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetRPMetadataDigestAlgorithm", metadata.rp_metadata_digest_alg, w);
}

const char*
oidfed_cfg_set_fe_metadata_url(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetRPMetadataDigestAlgorithm", metadata.rp_metadata_digest_alg, w);
}

const char*
oidfed_cfg_set_fe_metadata_digest(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetFEMetadataDigestAlgorithm", metadata.fe_metadata_digest_alg, w);
}

const char*
oidfed_cfg_set_fe_metadata_digest_alg(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetFEMetadataDigestAlgorithm", metadata.fe_metadata_digest_alg, w);
}

const char*
oidfed_cfg_add_rp_redirect_uri(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
    if (cfg->metadata.rp_redirect_uris_sz >= CONFIG_METADATA_REDIRECT_URIS_MAX) {
        return "OidfedAddRPRedirectURI: too many redirect URIs";
    }
    cfg->metadata.rp_redirect_uris[cfg->metadata.rp_redirect_uris_sz++] = apr_pstrdup(parms->pool, w);
    return NULL;
}

const char*
oidfed_cfg_set_application_type(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetApplicationType", metadata.application_type, w);
}

const char*
oidfed_cfg_set_client_name(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetClientName", metadata.client_name, w);
}

const char*
oidfed_cfg_set_organization_name(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetOrganizationName", metadata.organization_name, w);
}

const char*
oidfed_cfg_set_logo_uri(cmd_parms* parms, void* mconfig, const char* w) {
    SAFE_COPY_CONFIG(parms, "OidfedSetLogoURI", metadata.logo_uri, w);
}

const char*
oidfed_cfg_add_client_reg_type(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
    if (cfg->metadata.client_registration_types_sz >= CONFIG_METADATA_CLIENT_REG_TYPES_MAX) {
        return "OidfedAddClientRegistrationType: too many client registration types";
    }
    cfg->metadata.client_registration_types[cfg->metadata.client_registration_types_sz++] = apr_pstrdup(parms->pool, w);
    return NULL;
}

const char*
oidfed_cfg_add_response_type(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
    if (cfg->metadata.response_types_sz >= CONFIG_METADATA_RESPONSE_TYPES_MAX) {
        return "OidfedAddResponseType: too many response types";
    }
    cfg->metadata.response_types[cfg->metadata.response_types_sz++] = apr_pstrdup(parms->pool, w);
    return NULL;
}

const char*
oidfed_cfg_add_grant_type(cmd_parms* parms, void* mconfig, const char* w) {
    struct oidfed_config* const cfg = ap_get_module_config(parms->server->module_config, &oidfed);
    if (cfg->metadata.grant_types_sz >= CONFIG_METADATA_GRANT_TYPES_MAX) {
        return "OidfedAddGrantType: too many grant types";
    }
    cfg->metadata.grant_types[cfg->metadata.grant_types_sz++] = apr_pstrdup(parms->pool, w);
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

int
slurp_file(apr_pool_t* pool, const char* path, char** out_chars, size_t* out_chars_sz) {
    FILE* f = fopen(path, "r");
    if (!f) return errno;

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

            alloc_sz = (size_t)((double)alloc_sz * 1.5);
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
    return 0;
}

static const char*
try_load_key_from_file(server_rec* sv,
                       const char* path,
                       const char* key_type,
                       struct oidfed_signer* signer) {
    char* chars = NULL;
    size_t chars_sz = 0;
    int errc = slurp_file(sv->process->pool, path, &chars, &chars_sz);
    if (errc != 0) {
        explicit_bzero(chars, chars_sz);
        return apr_psprintf(
            sv->process->pool, "Failed to load %s key: error %d: %s",
            key_type,
            errc,
            strerror(errc)
        );
    }

    // Remember to explicitly purge key from memory regardless of success after
    // this call
    *signer = oidfedSignerCreateFromPEM(sv, chars, chars_sz, &errc);
    explicit_bzero(chars, chars_sz);
    if (errc != 0) {
        return apr_psprintf(
            sv->process->pool, "Failed to load %s key: error %d: error in go runtime",
            key_type,
            errc
        );
    }
    return NULL;
}

static const char*
try_load_signing_algorithm(server_rec* sv,
                           char* alg,
                           const char* alg_type,
                           struct oidfed_signature_algorithm* out_alg) {
    ap_log_error(
        APLOG_MARK, APLOG_DEBUG, 0, sv,
        "(worker:%d) finding signing algorithm for %s: %s",
        getpid(), alg_type, alg
    );
    bool succ = false;
    *out_alg = oidfedSignatureAlgorithmGet(
        sv, alg, &succ
    );
    if (!succ) {
        return apr_psprintf(
            sv->process->pool, "Failed to load %s signing key: unknown signature algorithm: %s",
            alg_type,
            alg
        );
    }
    return NULL;
}

void
oidfed_worker_runtime_init(server_rec* sv, struct oidfed_config* config) {
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "(worker:%d) initiating worker (%d:%d)", getpid(), getuid(), getgid());
    if (config->worker_cfg.runtime != 0) return;

    struct oidfed_worker_runtime* runtime =
            config->worker_cfg.runtime =
            apr_pcalloc(sv->process->pool, sizeof(struct oidfed_worker_runtime));
    apr_pool_cleanup_register(sv->process->pool, runtime, oidfed_worker_runtime_uninit, NULL);

    runtime->server = sv;

    runtime->trust_anchors = apr_pcalloc(
        sv->process->pool,
        config->trust_anchors_sz * sizeof(struct oidfed_trust_anchor)
    );
    for (size_t i = 0; i < config->trust_anchors_sz; ++i) {
        const char* trust_anchor_id = config->trust_anchors[i];
        runtime->trust_anchors[i] = oidfedTrustAnchorCreate(sv, (char*) trust_anchor_id);
    }
    runtime->trust_anchors_sz = config->trust_anchors_sz;

    runtime->collector = oidfedCollectorCreateSmart(
        sv,
        runtime->trust_anchors,
        runtime->trust_anchors_sz
    );

    runtime->filter = oidfedEmptyCollectionFilter(sv);
    for (const struct oidfed_filter_config* it = config->filters;
         it;
         it = it->next) {
        config_filter_append(sv, config, it, &runtime->filter);
    }

    const char* error_str = 0;

    struct oidfed_signer fed_signer;
    error_str = try_load_key_from_file(
        sv,
        config->federation_signing_key_file,
        "federation",
        &fed_signer
    );
    if (error_str) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv, "%s", error_str);
        return;
    }

    struct oidfed_signer oidc_signer;
    error_str = try_load_key_from_file(
        sv,
        config->oidc_signing_key_file,
        "oidc",
        &oidc_signer
    );
    if (error_str) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv, "%s", error_str);
        return;
    }

    error_str = try_load_signing_algorithm(
        sv, config->federation_signing_alg, "federation", &runtime->federation_signing_alg
    );
    if (error_str) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv, "%s", error_str);
        return;
    }
    error_str = try_load_signing_algorithm(sv, config->oidc_signing_alg, "oidc", &runtime->oidc_signing_alg);
    if (error_str) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv, "%s", error_str);
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sv, "(worker:%d) creating key storage for federation", getpid());
    runtime->federation_key_storage = oidfedSingleKeyStorageCreate(
        sv, fed_signer, runtime->federation_signing_alg
    );
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sv, "(worker:%d) creating signer for federation", getpid());
    runtime->federation_signer = oidfedSingleKeyStorageAsVersatileSigner(&runtime->federation_key_storage);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "(worker:%d) creating key storage for oidc", getpid());
    runtime->oidc_key_storage = oidfedSingleKeyStorageCreate(
        sv, oidc_signer, runtime->oidc_signing_alg
    );
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sv, "(worker:%d) creating signer for oidc", getpid());
    runtime->oidc_signer = oidfedSingleKeyStorageAsVersatileSigner(&runtime->oidc_key_storage);

    struct in_memory_storage_impl* storage_impl = apr_pcalloc(sv->process->pool, sizeof(struct in_memory_storage_impl));
    storage_impl->hash = apr_hash_make(sv->process->pool);
    apr_thread_mutex_create(&storage_impl->mutex, APR_THREAD_MUTEX_DEFAULT, sv->process->pool);

    runtime->session_storage.impl = storage_impl;
    runtime->session_storage.set = in_memory_set;
    runtime->session_storage.get = in_memory_get;
    runtime->session_storage.remove = in_memory_remove;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sv, "(worker:%d) creating entity metadata objects", getpid());
    runtime->rp_metadata = oidfedMetadataCreate(sv);
    const struct oidfed_openid_relying_party_metadata rp = oidfedOpenIDRelyingPartyMetadataCreate(sv);
    oidfedOpenIDRelyingPartyMetadataSetApplicationType(sv, rp, config->metadata.application_type);
    oidfedOpenIDRelyingPartyMetadataSetClientName(sv, rp, config->metadata.client_name);
    oidfedOpenIDRelyingPartyMetadataSetOrganizationName(sv, rp, config->metadata.organization_name);
    oidfedOpenIDRelyingPartyMetadataSetClientRegistrationTypes(
        sv, rp, config->metadata.client_registration_types,
        config->metadata.client_registration_types_sz
    );
    oidfedOpenIDRelyingPartyMetadataSetRedirectUris(
        sv, rp, config->metadata.rp_redirect_uris,
        config->metadata.rp_redirect_uris_sz
    );
    oidfedOpenIDRelyingPartyMetadataSetResponseTypes(
        sv, rp, config->metadata.response_types,
        config->metadata.response_types_sz
    );
    oidfedOpenIDRelyingPartyMetadataSetGrantTypes(
        sv, rp, config->metadata.grant_types,
        config->metadata.grant_types_sz
    );
    oidfedOpenIDRelyingPartyMetadataSetLogoURI(sv, rp, config->metadata.logo_uri);
    oidfedOpenIDRelyingPartyMetadataSetJWKSFromKeyStorage(sv, rp, runtime->federation_key_storage);
    oidfedMetadataSetRPMetadata(sv, runtime->rp_metadata, rp.impl);

    const struct oidfed_federation_entity_metadata entity = oidfedFederationEntityMetadataCreate(sv);
    oidfedFederationEntityMetadataSetLogoURI(sv, entity, config->metadata.logo_uri);
    oidfedFederationEntityMetadataSetOrganizationName(sv, entity, config->metadata.organization_name);
    oidfedMetadataSetFederationEntityMetadata(sv, runtime->rp_metadata, entity.impl);

    int errc = 0;
    runtime->leaf = oidfedFederationLeafCreate(
        sv, config->entity_id,
        0, 0,
        runtime->trust_anchors, runtime->trust_anchors_sz,
        runtime->federation_signer,
        runtime->oidc_signer,
        runtime->rp_metadata,
        &errc
    );
    if (errc != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv, "Failed to create federation leaf: error code %d", errc);
        return;
    }

    // After success, set the owner pid; this can act as a sanity check that we did not break things
    // in a way that made httpd give this object to another worker somehow.
    runtime->owner_pid = getpid();
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv, "(worker:%d) initialized worker, ready to work", getpid());
}

void
oidfed_worker_config_init(struct oidfed_worker_config* cfg) {
    cfg->lazy_load_symbols = CONFIG_DEFAULT_LAZY_LOAD_SYMBOLS;
}

void
oidfed_config_init(struct oidfed_config* cfg) {
    oidfed_worker_config_init(&cfg->worker_cfg);

    strlcpy(cfg->login_url, CONFIG_DEFAULT_LOGIN_PATH, sizeof(cfg->login_url));
    strlcpy(cfg->entity_id, CONFIG_DEFAULT_ENTITY_ID, sizeof(cfg->entity_id));

    strlcpy(
        cfg->federation_signing_key_file, CONFIG_DEFAULT_FEDERATION_KEY_FILE,
        sizeof(cfg->federation_signing_key_file)
    );
    strlcpy(cfg->federation_signing_alg, CONFIG_DEFAULT_FED_SIGNALG, sizeof(cfg->federation_signing_alg));

    strlcpy(cfg->oidc_signing_key_file, CONFIG_DEFAULT_OIDC_KEY_FILE, sizeof(cfg->oidc_signing_key_file));
    strlcpy(cfg->oidc_signing_alg, CONFIG_DEFAULT_OIDC_SIGNALG, sizeof(cfg->oidc_signing_alg));

    strlcpy(cfg->metadata.rp_metadata_url, CONFIG_DEFAULT_METADATA_URL, sizeof(cfg->metadata.rp_metadata_url));
    strlcpy(cfg->metadata.rp_metadata_digest, CONFIG_DEFAULT_METADATA_DIGEST, sizeof(cfg->metadata.rp_metadata_digest));
    strlcpy(
        cfg->metadata.rp_metadata_digest_alg, CONFIG_DEFAULT_METADATA_DIGEST_ALG,
        sizeof(cfg->metadata.rp_metadata_digest_alg)
    );

    strlcpy(cfg->metadata.fe_metadata_url, CONFIG_DEFAULT_METADATA_URL, sizeof(cfg->metadata.fe_metadata_url));
    strlcpy(cfg->metadata.fe_metadata_digest, CONFIG_DEFAULT_METADATA_DIGEST, sizeof(cfg->metadata.fe_metadata_digest));
    strlcpy(
        cfg->metadata.fe_metadata_digest_alg, CONFIG_DEFAULT_METADATA_DIGEST_ALG,
        sizeof(cfg->metadata.fe_metadata_digest_alg)
    );

    strlcpy(cfg->metadata.application_type, CONFIG_DEFAULT_APPLICATION_TYPE, sizeof(cfg->metadata.application_type));
    strlcpy(cfg->metadata.client_name, CONFIG_DEFAULT_CLIENT_NAME, sizeof(cfg->metadata.client_name));
    strlcpy(cfg->metadata.organization_name, CONFIG_DEFAULT_ORGANIZATION_NAME, sizeof(cfg->metadata.organization_name));
    strlcpy(cfg->metadata.logo_uri, CONFIG_DEFAULT_LOGO_URI, sizeof(cfg->metadata.logo_uri));

    cfg->metadata.client_registration_types_sz = CONFIG_DEFAULT_CLIENT_REG_TYPES_SZ;
    cfg->metadata.client_registration_types[0] = CONFIG_DEFAULT_CLIENT_REG_TYPE;

    cfg->metadata.rp_redirect_uris_sz = CONFIG_DEFAULT_REDIRECT_URIS_SZ;
    cfg->metadata.rp_redirect_uris[0] = CONFIG_DEFAULT_REDIRECT_URI;

    cfg->metadata.response_types_sz = CONFIG_DEFAULT_RESPONSE_TYPES_SZ;
    cfg->metadata.response_types[0] = CONFIG_DEFAULT_RESPONSE_TYPE;

    cfg->metadata.grant_types_sz = CONFIG_DEFAULT_GRANT_TYPES_SZ;
    cfg->metadata.grant_types[0] = CONFIG_DEFAULT_GRANT_TYPE;

    cfg->trust_anchors_sz = 0;
    cfg->authority_hints_sz = 0;
    cfg->filters = NULL;
}
