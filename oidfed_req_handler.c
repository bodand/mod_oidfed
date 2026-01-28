#include <ap_config.h>
#include <assert.h>
#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>

#include <oidfed_config.h>
#include <oidfed_wrap_loader.h>
#include <oidfed_req_handler.h>

static int
req_login_ui_handler(const struct oidfed_config* config, request_rec* r);

static int
req_well_known_handler(const struct oidfed_config* config, request_rec* r);

int
oidfed_req_handler(request_rec* r) {
    if (strcmp(r->handler, "oidfed") != CMP_EQ) return DECLINED;
    if (!r->uri) return DECLINED;

    const struct oidfed_config* config = ap_get_module_config(r->server->module_config,
                                                              &oidfed);

    assert(config->worker_cfg.runtime->owner_pid == getpid() && "mismatched owner pid");

    if (strcmp(r->uri, OIDFED_WELL_KNOWN_PATH) == CMP_EQ) {
        return req_well_known_handler(config, r);
    }
    if (strcmp(r->uri, config->login_url) == CMP_EQ) {
        return req_login_ui_handler(config, r);
    }

    return HTTP_NOT_FOUND;
}

int
req_login_ui_handler(const struct oidfed_config* config, request_rec* r) {
    struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;

    ap_rputs("<html><body><h1>Trust-anchors:</h1><ul>", r);

    for (size_t i = 0; i < rt->trust_anchors_sz; i++) {
        const struct oidfed_trust_anchor trust_anchor = rt->trust_anchors[i];

        ap_rprintf(r, "<li><h2>%s</h2><h3>OPs:</h3><ul>", trust_anchor.entity_id);

        struct oidfed_collected_entity* entities = NULL;
        size_t entities_sz = 0;
        oidfedCollectorCollectVerifiedEntitiesWithFilter(r, trust_anchor,
                                                         &rt->collector,
                                                         rt->filter,
                                                         &entities,
                                                         &entities_sz);

        for (size_t j = 0; j < entities_sz; j++) {
            bool printed = false;
            struct oidfed_collected_entity_ui_enumerator enumerator =
                    oidfedCollectedEntityEnumerateUi(r, entities[j]);
            while (oidfedCollectedEntityNextUi(r, &enumerator)) {
                struct oidfed_ui_info ui = oidfedCollectedEntityGetUiValue(r, &enumerator);
                ap_rprintf(r, "<li>%s (<a href=\"%s/.well-known/openid-federation\">%s</a>)</li>",
                           ui.display_name,
                           entities[j].entity_id,
                           entities[j].entity_id
                );
                printed = true;
                oidfedUiInfoDestroy(r, &ui);
            }
            oidfedCollectedEntityFinishUi(r, &enumerator);

            if (!printed) {
                ap_rprintf(r, "<li><a href=\"%s/.well-known/openid-federation\">%s</a></li>",
                           entities[j].entity_id,
                           entities[j].entity_id);
            }

            oidfedCollectedEntityDestroy(r, &entities[j]);
        }

        free(entities);
        ap_rputs("</ul></li>", r);
    }

    ap_rputs("</ul></body></html>", r);
    return OK;
}

int
req_well_known_handler(const struct oidfed_config* config, request_rec* r) {
    return OK;
}
