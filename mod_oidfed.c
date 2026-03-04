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

    if (str_empty(new->login_url))
        strlcpy(result->login_url, base->login_url, sizeof(result->login_url));
    else
        strlcpy(result->login_url, new->login_url, sizeof(result->login_url));

    if (str_empty(new->entity_id))
        strlcpy(result->entity_id, base->entity_id, sizeof(result->entity_id));
    else
        strlcpy(result->entity_id, new->entity_id, sizeof(result->entity_id));

    if (str_empty(new->federation_signing_key_file))
        strlcpy(result->federation_signing_key_file, base->federation_signing_key_file, sizeof(result->federation_signing_key_file));
    else
        strlcpy(result->federation_signing_key_file, new->federation_signing_key_file, sizeof(result->federation_signing_key_file));

    result->trust_anchors_sz = base->trust_anchors_sz + new->trust_anchors_sz;
    if (result->trust_anchors_sz > CONFIG_TRUST_ANCHORS_MAX) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, "Too many trust anchors");
        return NULL;
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
        return NULL;
    }
    memcpy(result->authority_hints,
           base->authority_hints,
           sizeof(char*) * base->authority_hints_sz);
    memcpy(result->authority_hints + base->authority_hints_sz,
           new->authority_hints,
           sizeof(char*) * new->authority_hints_sz);

    if (new->filters) {
        result->filters = new->filters;
    }
    else {
        result->filters = (struct oidfed_filter_config*) base->filters;
    }

    return result;
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
    if (strcmp(r->uri, login_url) == CMP_EQ) {
        r->handler = "oidfed";
        return OK;
    }

    return DECLINED;
}
