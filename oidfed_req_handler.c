#include <ap_config.h>
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

    const struct oidfed_config* config = ap_get_module_config(r->per_dir_config, &oidfed_module);

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

int
req_well_known_handler(const struct oidfed_config* config, request_rec* r) {
    return OK;
}
