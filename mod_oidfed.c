#include <ap_config.h>
#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>

#include <oidfed_config.h>
#include <oidfed_req_handler.h>
#include <oidfed_wrap_loader.h>

void
worker_init_handler(apr_pool_t* pchild, server_rec* s);

int
oidfed_type_dispatcher(request_rec* r);

static void
oidfed_register_hooks(apr_pool_t* p) {
    ap_hook_handler(oidfed_req_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(worker_init_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_type_checker(oidfed_type_dispatcher, NULL, NULL, APR_HOOK_MIDDLE);
}

void*
oidfed_create_dir_config(apr_pool_t* apr_pool, char* dir) {
    struct oidfed_config* const cfg = apr_pcalloc(apr_pool, sizeof(struct oidfed_config));
    strcpy(cfg->login_url, "/login");
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

    result->trust_anchors_sz = base->trust_anchors_sz + new->trust_anchors_sz;
    if (result->trust_anchors_sz > CONFIG_TRUST_ANCHORS_MAX) {
        errno = EINVAL;
        return NULL;
    }

    memcpy(result->trust_anchors,
           base->trust_anchors,
           sizeof(char*) * base->trust_anchors_sz);
    memcpy(result->trust_anchors + base->trust_anchors_sz,
           new->trust_anchors,
           sizeof(char*) * new->trust_anchors_sz);

    return result;
}

void*
oidfed_merge_server_config(apr_pool_t* apr_pool, void* base_conf, void* new_conf) {
    return oidfed_merge_dir_config(apr_pool, base_conf, new_conf);
}

module AP_MODULE_DECLARE_DATA oidfed_module = {
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
        struct oidfed_config* conf = ap_get_module_config(s->module_config, &oidfed_module);
        if (conf) {
            oidfed_worker_init(&conf->worker_cfg, s->process->pconf);
        }
    }
}

int
oidfed_type_dispatcher(request_rec* r) {
    if (!r->uri) return DECLINED;

    const struct oidfed_config* config = ap_get_module_config(r->per_dir_config, &oidfed_module);
    if (strcmp(r->uri, OIDFED_WELL_KNOWN_PATH) == CMP_EQ) {
        r->handler = "oidfed";
        return OK;
    }
    if (strcmp(r->uri, config->login_url) == CMP_EQ) {
        r->handler = "oidfed";
        return OK;
    }

    return DECLINED;
}

