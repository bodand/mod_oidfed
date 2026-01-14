#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"

#include <oidfed_wrap_loader.h>

#include <dlfcn.h>
#include <oidfed_wrap.h>

#define CMP_EQ 0

#define CONFIG_TRUST_ANCHORS_MAX 100

struct oidfed_config {
    struct oidfed_worker_config worker_cfg;

    const char* trust_anchors[CONFIG_TRUST_ANCHORS_MAX];
    size_t trust_anchors_sz;
};

const char*
oidfed_add_trust_anchor(cmd_parms* cmd, void* cfg, const char* entity_id) {
    struct oidfed_config* const config = cfg;
    if (config->trust_anchors_sz == SIZE_MAX) return "Too many trust anchors in configuration";

    config->trust_anchors[config->trust_anchors_sz++] = entity_id;

    return NULL;
}

static const command_rec oidfed_cmds[] = {
    AP_INIT_TAKE1("AddTrustAnchor", oidfed_add_trust_anchor, NULL, RSRC_CONF, "Add given trust anchor to federation"),
    {NULL}
};

static int
oidfed_handler(request_rec* r);

void
worker_init_handler(apr_pool_t* pchild, server_rec* server_rec);

static void
oidfed_register_hooks(apr_pool_t* p) {
    ap_hook_handler(oidfed_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(worker_init_handler, NULL, NULL, APR_HOOK_FIRST);
}

void*
oidfed_create_dir_config(apr_pool_t* apr_pool, char* dir) {
    struct oidfed_config* const cfg = apr_pcalloc(apr_pool, sizeof(struct oidfed_config));
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
worker_init_handler(apr_pool_t* pchild, server_rec* s)
{
    if (!s) return;
    
    struct oidfed_config* conf = ap_get_module_config(s->module_config, &oidfed_module);
    if (conf) {
        oidfed_worker_init(&conf->worker_cfg, s->process->pconf);
    }
}

static int
oidfed_handler(request_rec* r) {
    if (strcmp(r->handler, "oidfed") != CMP_EQ) return DECLINED;

    const struct oidfed_config* config = ap_get_module_config(r->per_dir_config, &oidfed_module);

    struct oidfed_collection_filter filter = oidfedEmptyCollectionFilter();
    oidfedCollectionFilterAppend(&filter, oidfedEntityCollectionFilterOPs());

    struct oidfed_trust_anchor* tas = apr_pcalloc(
        r->pool, config->trust_anchors_sz * sizeof(struct oidfed_trust_anchor));
    if (!tas) return HTTP_INTERNAL_SERVER_ERROR;

    for (size_t i = 0; i < config->trust_anchors_sz; i++) {
        const char* trust_anchor_id = config->trust_anchors[i];
        tas[i] = oidfedTrustAnchorCreate((char*) trust_anchor_id);
    }

    struct oidfed_collector collector = oidfedCollectorCreateSmart(tas, config->trust_anchors_sz);

    ap_rputs("<html><body><h1>Trust-anchors:</h1><ul>", r);

    for (size_t i = 0; i < config->trust_anchors_sz; i++) {
        const struct oidfed_trust_anchor trust_anchor = tas[i];

        ap_rprintf(r, "<li><h2>%s</h2><h3>OPs:</h3><ul>", trust_anchor.entity_id);

        struct oidfed_collected_entity* entities = NULL;
        size_t entities_sz = 0;
        oidfedCollectorCollectVerifiedEntitiesWithFilter(trust_anchor, &collector, filter, &entities, &entities_sz);

        for (size_t j = 0; j < entities_sz; j++) {
            bool printed = false;
            struct oidfed_collected_entity_ui_enumerator enumerator =
                    oidfedCollectedEntityEnumerateUi(entities[j]);
            while (oidfedCollectedEntityNextUi(&enumerator)) {
                struct oidfed_ui_info ui = oidfedCollectedEntityGetUiValue(&enumerator);
                ap_rprintf(r, "<li>%s (<a href=\"%s/.well-known/openid-federation\">%s</a>)</li>",
                           ui.display_name,
                           entities[j].entity_id,
                           entities[j].entity_id
                );
                printed = true;
                oidfedUiInfoDestroy(&ui);
            }
            oidfedCollectedEntityFinishUi(&enumerator);

            if (!printed) {
                ap_rprintf(r, "<li><a href=\"%s/.well-known/openid-federation\">%s</a></li>",
                    entities[j].entity_id,
                    entities[j].entity_id);
            }

            oidfedCollectedEntityDestroy(&entities[j]);
        }

        free(entities);
        ap_rputs("</ul></li>", r);
    }

    ap_rputs("</ul></body></html>", r);
    oidfedCollectionFilterDestroy(&filter);
    oidfedCollectorDestroy(&collector);

    for (size_t i = 0; i < config->trust_anchors_sz; i++) {
        oidfedTrustAnchorDestroy(&tas[i]);
    }

    return OK;
}
