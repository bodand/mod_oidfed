#include <ap_config.h>
#include <assert.h>
#include <httpd.h>

#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <apr_strings.h>
#include <apr_escape.h>

#include <oidfed_config.h>
#include <oidfed_req_handler.h>
#include <oidfed_wrap_loader.h>

#include <util_script.h>

static char*
construct_auth_url(request_rec* r, const struct oidfed_config* config,
                   struct oidfed_openid_provider_metadata op_metadata) {
    char* auth_endpoint = oidfedOpenIDProviderMetadataGetAuthorizationEndpoint(r, op_metadata);
    if (!auth_endpoint) return NULL;

    char* issuer = oidfedOpenIDProviderMetadataGetIssuer(r, op_metadata);
    if (!issuer) {
        free(auth_endpoint);
        return NULL;
    }

    const struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;
    const struct oidfed_request_producer producer = oidfedFederationLeafGetRequestObjectProducer(r, rt->leaf);
    if (!producer.impl) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to create request object producer");
        free(issuer);
        free(auth_endpoint);
        return NULL;
    }

    struct oidfed_map request_values = oidfCreateMap(r);
    oidfMapSetString(r, request_values, "response_type", "code");
    oidfMapSetString(r, request_values, "client_id", (char*)config->entity_id);
    oidfMapSetString(r, request_values, "scope", "openid");
    oidfMapSetString(r, request_values, "aud", issuer);
    if (config->metadata.rp_redirect_uris_sz > 0) {
        oidfMapSetString(r, request_values, "redirect_uri", config->metadata.rp_redirect_uris[0]);
    }

    // XXX - unsafe random
    char state[17];
    char nonce[17];
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 16; i++) {
        state[i] = charset[rand() % (sizeof(charset) - 1)];
        nonce[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    state[16] = '\0';
    nonce[16] = '\0';
    oidfMapSetString(r, request_values, "state", state);
    oidfMapSetString(r, request_values, "nonce", nonce);

    int errc = 0;
    struct oidfed_signed_bytes signed_request = oidfedRequestProducerProduceObject(r, producer, request_values, (struct oidfed_jws_headers){0}, NULL, 0, &errc);

    if (errc != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed produce object: %d", errc);
        oidfMapDestroy(r, &request_values);
        free(auth_endpoint);
        return NULL;
    }

    size_t jwt_sz = 0;
    char* jwt = oidfedSignedBytesGetData(r, signed_request, &jwt_sz);

    char* final_url = apr_psprintf(r->pool, "%s%cclient_id=%s&request=%s",
                                   auth_endpoint,
                                   strchr(auth_endpoint, '?') ? '&' : '?',
                                   apr_pescape_urlencoded(r->pool, config->entity_id),
                                   jwt);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Constructed Auth URL: %s", final_url);

    free(jwt);
    free(issuer);
    free(auth_endpoint);
    oidfedSignedBytesDestroy(r, &signed_request);
    oidfMapDestroy(r, &request_values);

    return final_url;
}

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
        const char* op_id = NULL;
        apr_table_t* args = NULL;
        ap_args_to_table(r, &args);
        if (args) {
            op_id = apr_table_get(args, "op");
        }

        // TODO: break up heavly nested code
        if (op_id) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Initiating login for OP: %s", op_id);
            const struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;
            struct oidfed_trust_resolver resolver = oidfedTrustResolverCreate(r, (char*)op_id, rt->trust_anchors, rt->trust_anchors_sz);
            struct oidfed_trust_chains chains = oidfedTrustResolverResolveToValidChains(r, resolver);

            if (oidfedTrustChainsCount(r, chains) > 0) {
                struct oidfed_trust_chain chain = oidfedTrustChainsGet(r, chains, 0);
                int errc = 0;
                struct oidfed_metadata metadata = oidfedTrustChainGetMetadata(r, chain, &errc);

                if (errc == 0) {
                    struct oidfed_openid_provider_metadata op_metadata = oidfedMetadataGetOPMetadata(r, metadata);
                    if (op_metadata.impl != 0) {
                        char* auth_url = construct_auth_url(r, config, op_metadata);
                        if (auth_url) {
                            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Redirecting to OP auth URL: %s", auth_url);
                            
                            oidfedOpenIDProviderMetadataDestroy(r, &op_metadata);
                            oidfedMetadataDestroy(r, &metadata);
                            oidfedTrustChainDestroy(r, &chain);
                            oidfedTrustChainsDestroy(r, &chains);
                            oidfedTrustResolverDestroy(r, &resolver);
                            
                            apr_table_set(r->headers_out, "Location", auth_url);
                            return HTTP_MOVED_TEMPORARILY;
                        } else {
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to construct auth URL for OP: %s", op_id);
                        }
                    } else {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to get OP metadata for OP: %s", op_id);
                    }
                    oidfedMetadataDestroy(r, &metadata);
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to get metadata from trust chain for OP: %s, error: %d", op_id, errc);
                }
                oidfedTrustChainDestroy(r, &chain);
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No valid trust chains found for OP: %s", op_id);
            }
            oidfedTrustChainsDestroy(r, &chains);
            oidfedTrustResolverDestroy(r, &resolver);
        }

        return req_login_ui_handler(config, r);
    }

    return HTTP_NOT_FOUND;
}

int
req_login_ui_handler(const struct oidfed_config* config, request_rec* r) {
    struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;

    ap_set_content_type(r, "text/html");
    ap_rputs("<html><body><h1>Trust-anchors:</h1><ul>", r);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Rendering login UI with %lu trust anchors",
        rt->trust_anchors_sz);

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
                ap_rprintf(r, "<li>%s (<a href=\"%s?op=%s\">%s</a>)</li>",
                           ui.display_name,
                           config->login_url,
                           entities[j].entity_id,
                           entities[j].entity_id
                );
                printed = true;
                oidfedUiInfoDestroy(r, &ui);
            }
            oidfedCollectedEntityFinishUi(r, &enumerator);

            if (!printed) {
                ap_rprintf(r, "<li><a href=\"%s?op=%s\">%s</a></li>",
                           config->login_url,
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
    struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;

    int errc = 0;
    char* bytes;
    size_t bytes_sz = 0;

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Producing JWT: %lu", rt->leaf.impl);
    if ((errc = oidfedFederationLeafGetAsJWT(r, rt->leaf, &bytes, &bytes_sz)) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to produce JWT: error code %d", errc);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_set_content_type(r, "application/entity-statement+jwt");

    while (bytes_sz > INT_MAX) {
        ap_rwrite(bytes, INT_MAX, r);
        bytes += INT_MAX;
        bytes_sz -= INT_MAX;
    }
    ap_rwrite(bytes, (int) bytes_sz, r);

    free(bytes);
    return OK;
}

static bool
str_empty(const char* str) {
    return str[0] == '\0';
}

int
oidfed_authenticate_user(request_rec* r) {
    const char* auth_type = ap_auth_type(r);
    if (!auth_type || strcasecmp(auth_type, "Oidfed") != CMP_EQ) {
        return DECLINED;
    }

    const struct oidfed_config* config = ap_get_module_config(r->server->module_config,
                                                              &oidfed);

    const char* login_url = str_empty(config->login_url) ? CONFIG_DEFAULT_LOGIN_PATH : config->login_url;

    // TODO: Check for session cookie/token here.
    // For now, we assume if we reached here and it's not the login page, we need to redirect.

    if (strcmp(r->uri, login_url) == CMP_EQ) {
        return DECLINED;
    }

    r->status = HTTP_MOVED_TEMPORARILY;
    apr_table_set(r->headers_out, "Location", login_url);
    return HTTP_MOVED_TEMPORARILY;
}
