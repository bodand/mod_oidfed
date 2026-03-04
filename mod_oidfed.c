#include <ap_config.h>
#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include <oidfed_config.h>
#include <oidfed_req_handler.h>
#include <oidfed_wrap_loader.h>

static bool
str_empty(const char* str) {
    return str[0] == '\0';
}

void
worker_init_handler(apr_pool_t* pchild, server_rec* s);

int
oidfed_type_dispatcher(request_rec* r);

static void
oidfed_register_hooks(apr_pool_t* p) {
    ap_hook_handler(oidfed_req_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(worker_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_type_checker(oidfed_type_dispatcher, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_authn(oidfed_authenticate_user, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
}

void*
oidfed_create_dir_config(apr_pool_t* apr_pool, char* dir) {
    struct oidfed_config* const cfg = apr_pcalloc(apr_pool, sizeof(struct oidfed_config));
    oidfed_config_init(cfg);
    return cfg;
}

void*
oidfed_create_server_config(apr_pool_t* apr_pool, server_rec* s) {
    return oidfed_create_dir_config(apr_pool, NULL);
}

void*
oidfed_merge_dir_config(apr_pool_t* apr_pool, void* base_conf, void* new_conf) {
    const struct oidfed_config* const base = base_conf;
    const struct oidfed_config* const new = new_conf;
    struct oidfed_config* const result = oidfed_create_dir_config(apr_pool, NULL);

    result->worker_cfg.lazy_load_symbols = new->worker_cfg.lazy_load_symbols;

    const struct oidfed_config* login_base = new;
    if (str_empty(new->login_url)) login_base = base;
    if (strlcpy(result->login_url,
                login_base->login_url,
                sizeof(result->login_url)) > sizeof(result->login_url)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, "Login path too long");
        goto error;
    }

    const struct oidfed_config* entity_base = new;
    if (str_empty(new->entity_id)) entity_base = base;
    if (strlcpy(result->entity_id,
                entity_base->entity_id,
                sizeof(result->entity_id)) > sizeof(result->entity_id)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, "Entity ID too long");
        goto error;
    }

    const size_t key_fname_size = sizeof(result->federation_signing_key_file);
    const struct oidfed_config* metadata_base = new;
    if (str_empty(new->federation_signing_key_file)) metadata_base = base;
    if (strlcpy(result->federation_signing_key_file,
                metadata_base->federation_signing_key_file,
                key_fname_size) >= key_fname_size) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, "Federation signing key file path too long");
        goto error;
    }

    result->trust_anchors_sz = base->trust_anchors_sz + new->trust_anchors_sz;
    if (result->trust_anchors_sz > CONFIG_TRUST_ANCHORS_MAX) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, "Too many trust anchors");
        goto error;
    }

    memcpy(result->trust_anchors,
           base->trust_anchors,
           sizeof(char*) * base->trust_anchors_sz);
    memcpy(result->trust_anchors + base->trust_anchors_sz,
           new->trust_anchors,
           sizeof(char*) * new->trust_anchors_sz);

    result->authority_hints_sz = base->authority_hints_sz + new->authority_hints_sz;
    if (result->authority_hints_sz > CONFIG_AUTHORITY_HINTS_MAX) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, "Too many authority hints");
        goto error;
    }
    memcpy(result->authority_hints,
           base->authority_hints,
           sizeof(char*) * base->authority_hints_sz);
    memcpy(result->authority_hints + base->authority_hints_sz,
           new->authority_hints,
           sizeof(char*) * new->authority_hints_sz);

    result->filters = (struct oidfed_filter_config*) base->filters;
    if (new->filters) result->filters = new->filters;

    const struct oidfed_config* signing_base = new;
    if (str_empty(new->federation_signing_alg)) signing_base = base;
    strlcpy(result->federation_signing_alg, signing_base->federation_signing_alg,
            sizeof(result->federation_signing_alg));

    signing_base = new;
    if (str_empty(new->oidc_signing_key_file)) signing_base = base;
    strlcpy(result->oidc_signing_key_file, signing_base->oidc_signing_key_file,
            sizeof(result->oidc_signing_key_file));

    signing_base = new;
    if (str_empty(new->oidc_signing_alg)) signing_base = base;
    strlcpy(result->oidc_signing_alg, signing_base->oidc_signing_alg,
            sizeof(result->oidc_signing_alg));

    // Merge metadata
    const struct oidfed_config* meta_base = new;
    if (str_empty(new->metadata.rp_metadata_url)) meta_base = base;
    strlcpy(result->metadata.rp_metadata_url, meta_base->metadata.rp_metadata_url,
            sizeof(result->metadata.rp_metadata_url));

    meta_base = new;
    if (str_empty(new->metadata.rp_metadata_digest)) meta_base = base;
    strlcpy(result->metadata.rp_metadata_digest, meta_base->metadata.rp_metadata_digest,
            sizeof(result->metadata.rp_metadata_digest));

    meta_base = new;
    if (str_empty(new->metadata.rp_metadata_digest_alg)) meta_base = base;
    strlcpy(result->metadata.rp_metadata_digest_alg, meta_base->metadata.rp_metadata_digest_alg,
            sizeof(result->metadata.rp_metadata_digest_alg));

    meta_base = new;
    if (str_empty(new->metadata.fe_metadata_url)) meta_base = base;
    strlcpy(result->metadata.fe_metadata_url, meta_base->metadata.fe_metadata_url,
            sizeof(result->metadata.fe_metadata_url));

    meta_base = new;
    if (str_empty(new->metadata.fe_metadata_digest)) meta_base = base;
    strlcpy(result->metadata.fe_metadata_digest, meta_base->metadata.fe_metadata_digest,
            sizeof(result->metadata.fe_metadata_digest));

    meta_base = new;
    if (str_empty(new->metadata.fe_metadata_digest_alg)) meta_base = base;
    strlcpy(result->metadata.fe_metadata_digest_alg, meta_base->metadata.fe_metadata_digest_alg,
            sizeof(result->metadata.fe_metadata_digest_alg));

    meta_base = new;
    if (str_empty(new->metadata.application_type)) meta_base = base;
    strlcpy(result->metadata.application_type, meta_base->metadata.application_type,
            sizeof(result->metadata.application_type));

    meta_base = new;
    if (str_empty(new->metadata.client_name)) meta_base = base;
    strlcpy(result->metadata.client_name, meta_base->metadata.client_name,
            sizeof(result->metadata.client_name));

    meta_base = new;
    if (str_empty(new->metadata.organization_name)) meta_base = base;
    strlcpy(result->metadata.organization_name, meta_base->metadata.organization_name,
            sizeof(result->metadata.organization_name));

    meta_base = new;
    if (str_empty(new->metadata.logo_uri)) meta_base = base;
    strlcpy(result->metadata.logo_uri, meta_base->metadata.logo_uri,
            sizeof(result->metadata.logo_uri));

    // Arrays
    result->metadata.rp_redirect_uris_sz = base->metadata.rp_redirect_uris_sz + new->metadata.rp_redirect_uris_sz;
    if (result->metadata.rp_redirect_uris_sz > CONFIG_METADATA_REDIRECT_URIS_MAX) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, "Too many redirect URIs");
        goto error;
    }
    memcpy(result->metadata.rp_redirect_uris, base->metadata.rp_redirect_uris,
           sizeof(char*) * base->metadata.rp_redirect_uris_sz);
    memcpy(result->metadata.rp_redirect_uris + base->metadata.rp_redirect_uris_sz,
           new->metadata.rp_redirect_uris, sizeof(char*) * new->metadata.rp_redirect_uris_sz);

    result->metadata.client_registration_types_sz =
            base->metadata.client_registration_types_sz + new->metadata.client_registration_types_sz;
    if (result->metadata.client_registration_types_sz > CONFIG_METADATA_CLIENT_REG_TYPES_MAX) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, "Too many client registration types");
        goto error;
    }
    memcpy(result->metadata.client_registration_types, base->metadata.client_registration_types,
           sizeof(char*) * base->metadata.client_registration_types_sz);
    memcpy(result->metadata.client_registration_types + base->metadata.client_registration_types_sz,
           new->metadata.client_registration_types, sizeof(char*) * new->metadata.client_registration_types_sz);

    result->metadata.response_types_sz = base->metadata.response_types_sz + new->metadata.response_types_sz;
    if (result->metadata.response_types_sz > CONFIG_METADATA_RESPONSE_TYPES_MAX) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, "Too many response types");
        goto error;
    }
    memcpy(result->metadata.response_types, base->metadata.response_types,
           sizeof(char*) * base->metadata.response_types_sz);
    memcpy(result->metadata.response_types + base->metadata.response_types_sz,
           new->metadata.response_types, sizeof(char*) * new->metadata.response_types_sz);

    result->metadata.grant_types_sz = base->metadata.grant_types_sz + new->metadata.grant_types_sz;
    if (result->metadata.grant_types_sz > CONFIG_METADATA_GRANT_TYPES_MAX) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, "Too many grant types");
        goto error;
    }
    memcpy(result->metadata.grant_types, base->metadata.grant_types,
           sizeof(char*) * base->metadata.grant_types_sz);
    memcpy(result->metadata.grant_types + base->metadata.grant_types_sz,
           new->metadata.grant_types, sizeof(char*) * new->metadata.grant_types_sz);

    return result;

error:
    return NULL;
}

void*
oidfed_merge_server_config(apr_pool_t* apr_pool, void* base_conf, void* new_conf) {
    return oidfed_merge_dir_config(apr_pool, base_conf, new_conf);
}

module AP_MODULE_DECLARE_DATA oidfed = {
    STANDARD20_MODULE_STUFF,
    oidfed_create_dir_config,
    oidfed_merge_dir_config,
    oidfed_create_server_config,
    oidfed_merge_server_config,
    oidfed_cmds,
    oidfed_register_hooks
};

void
worker_init_handler(apr_pool_t* pchild, server_rec* s) {
    for (; s; s = s->next) {
        struct oidfed_config* conf = ap_get_module_config(s->module_config, &oidfed);
        if (conf) {
            oidfed_worker_init(&conf->worker_cfg, s->process->pconf);
            oidfed_worker_runtime_init(s, conf);
        }
    }
}

int
oidfed_type_dispatcher(request_rec* r) {
    if (!r->uri) return DECLINED;

    const struct oidfed_config* config = ap_get_module_config(r->server->module_config,
                                                              &oidfed);
    const char* login_url = str_empty(config->login_url) ? CONFIG_DEFAULT_LOGIN_PATH : config->login_url;
    if (strcmp(r->uri, OIDFED_WELL_KNOWN_PATH) == CMP_EQ) {
        r->handler = "oidfed";
        return OK;
    }
    for (size_t i = 0; i < config->metadata.rp_redirect_uris_sz; ++i) {
        const char* redirect_uri = config->metadata.rp_redirect_uris[i];
        if (redirect_uri && strcmp(r->uri, redirect_uri) == CMP_EQ) {
            r->handler = "oidfed";
            return OK;
        }
    }
    if (strcmp(r->uri, login_url) == CMP_EQ) {
        r->handler = "oidfed";
        return OK;
    }

    return DECLINED;
}
