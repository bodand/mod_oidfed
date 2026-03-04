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

#include <apr_hash.h>
#include <apr_thread_mutex.h>
#include <apr_time.h>
#include <util_cookies.h>
#include <oidfed_config.h>
#include <oidfed_req_handler.h>
#include <oidfed_wrap_loader.h>

#include <util_script.h>

static char*
construct_auth_url(request_rec* r, const struct oidfed_config* config,
                   struct oidfed_openid_provider_metadata op_metadata,
                   const char* op_id) {
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
    char state_bits[17];
    char nonce[17];
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 16; i++) {
        state_bits[i] = charset[rand() % (sizeof(charset) - 1)];
        nonce[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    state_bits[16] = '\0';
    nonce[16] = '\0';

    char* state = apr_psprintf(r->pool, "%s:%s", op_id, state_bits);
    oidfMapSetString(r, request_values, "state", state);
    oidfMapSetString(r, request_values, "nonce", nonce);

    // Save state in a temporary session to verify during redirect
    struct oidfed_session* temp_session = apr_pcalloc(r->server->process->pool, sizeof(struct oidfed_session));
    temp_session->sid = apr_pstrdup(r->server->process->pool, state_bits);
    temp_session->op_id = apr_pstrdup(r->server->process->pool, op_id);
    temp_session->expiry = apr_time_now() + apr_time_from_sec(300); // 5 minutes for state verification

    rt->session_storage.set(&rt->session_storage, temp_session);

    ap_cookie_write(r, OIDFED_SESSION_COOKIE, temp_session->sid, NULL, apr_time_from_sec(300), r->headers_out, r->err_headers_out, NULL);

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

static int
req_redirect_handler(const struct oidfed_config* config, request_rec* r);

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

    for (size_t i = 0; i < config->metadata.rp_redirect_uris_sz; i++) {
        if (strcmp(r->uri, config->metadata.rp_redirect_uris[i]) == CMP_EQ) {
            return req_redirect_handler(config, r);
        }
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
                        char* auth_url = construct_auth_url(r, config, op_metadata, op_id);
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

struct op_info {
    char* entity_id;
    char* display_name;
};

static int
compare_ops(const void* a, const void* b) {
    const struct op_info* op_a = (const struct op_info*)a;
    const struct op_info* op_b = (const struct op_info*)b;

    const char* name_a = op_a->display_name ? op_a->display_name : op_a->entity_id;
    const char* name_b = op_b->display_name ? op_b->display_name : op_b->entity_id;

    return strcmp(name_a, name_b);
}

int
req_login_ui_handler(const struct oidfed_config* config, request_rec* r) {
    struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;
    apr_hash_t* rendered_ops = apr_hash_make(r->pool);
    apr_array_header_t* ops_list = apr_array_make(r->pool, 10, sizeof(struct op_info));

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Collecting OPs from %lu trust anchors",
                  rt->trust_anchors_sz);

    for (size_t i = 0; i < rt->trust_anchors_sz; i++) {
        const struct oidfed_trust_anchor trust_anchor = rt->trust_anchors[i];

        struct oidfed_collected_entity* entities = NULL;
        size_t entities_sz = 0;
        oidfedCollectorCollectVerifiedEntitiesWithFilter(r, trust_anchor,
                                                         &rt->collector,
                                                         rt->filter,
                                                         &entities,
                                                         &entities_sz);

        for (size_t j = 0; j < entities_sz; j++) {
            if (apr_hash_get(rendered_ops, entities[j].entity_id, APR_HASH_KEY_STRING)) {
                oidfedCollectedEntityDestroy(r, &entities[j]);
                continue;
            }

            apr_hash_set(rendered_ops, entities[j].entity_id, APR_HASH_KEY_STRING, entities[j].entity_id);

            struct op_info* info = (struct op_info*)apr_array_push(ops_list);
            info->entity_id = apr_pstrdup(r->pool, entities[j].entity_id);
            info->display_name = NULL;

            struct oidfed_collected_entity_ui_enumerator enumerator =
                    oidfedCollectedEntityEnumerateUi(r, entities[j]);
            if (oidfedCollectedEntityNextUi(r, &enumerator)) {
                struct oidfed_ui_info ui = oidfedCollectedEntityGetUiValue(r, &enumerator);
                if (ui.display_name) {
                    info->display_name = apr_pstrdup(r->pool, ui.display_name);
                }
                oidfedUiInfoDestroy(r, &ui);
            }
            oidfedCollectedEntityFinishUi(r, &enumerator);

            oidfedCollectedEntityDestroy(r, &entities[j]);
        }

        free(entities);
    }

    qsort(ops_list->elts, ops_list->nelts, ops_list->elt_size, compare_ops);

    ap_set_content_type(r, "text/html");
    ap_rprintf(r, "<html>"
        "<head>"
        "<title>%s</title>"
        "<link rel=\"stylesheet\" type=\"text/css\" href=\"%s\">"
        "</head>"
        "<body>"
        "<h1 class=\"op-listing-header\">Available OPs:</h1>"
        "<ul class=\"op-listing\">",
        "Apache OpenID Federation",
        "oidfed.css");

    for (int i = 0; i < ops_list->nelts; i++) {
        struct op_info* info = &APR_ARRAY_IDX(ops_list, i, struct op_info);
        if (info->display_name) {
            ap_rprintf(r, "<li class=\"op-elem\" style=\"--op-index: %d\"><a href=\"%s?op=%s\">%s</a></li>",
                       i,
                       config->login_url,
                       info->entity_id,
                       info->display_name
            );
        } else {
            ap_rprintf(r,  "<li class=\"op-elem\" style=\"--op-index: %d\"><a href=\"%s?op=%s\">%s</a></li>",
                       i,
                       config->login_url,
                       info->entity_id,
                       info->entity_id);
        }
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

static int
req_redirect_handler(const struct oidfed_config* config, request_rec* r) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Handling OIDC redirect at: %s", r->uri);

    apr_table_t* args = NULL;
    ap_args_to_table(r, &args);
    if (!args) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: No query parameters received");
        return HTTP_BAD_REQUEST;
    }

    const char* code = apr_table_get(args, "code");
    const char* state = apr_table_get(args, "state");
    const char* error = apr_table_get(args, "error");
    const char* error_description = apr_table_get(args, "error_description");

    if (error) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect error: %s (%s)", error, error_description ? error_description : "no description");
        return HTTP_FORBIDDEN;
    }

    if (!code || !state) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: Missing code or state");
        return HTTP_BAD_REQUEST;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC redirect received code and state: state=%s", state);

    const struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;
    const char* sid_from_cookie = NULL;
    ap_cookie_read(r, OIDFED_SESSION_COOKIE, &sid_from_cookie, 0);

    // Retrieve OP identifier from state.
    char* op_id = apr_pstrdup(r->pool, state);
    char* sep = strchr(op_id, ':');
    const char* state_bits = NULL;
    if (sep) {
        *sep = '\0';
        state_bits = sep + 1;
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: Invalid state format (missing ':')");
        return HTTP_BAD_REQUEST;
    }

    if (!sid_from_cookie || strcmp(sid_from_cookie, state_bits) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: state/session mismatch (expected %s, got %s)", state_bits, sid_from_cookie ? sid_from_cookie : "null");
        return HTTP_FORBIDDEN;
    }

    struct oidfed_session* temp_session = rt->session_storage.get(&rt->session_storage, sid_from_cookie);
    if (temp_session) {
        rt->session_storage.remove(&rt->session_storage, sid_from_cookie);
    }

    if (!temp_session || temp_session->expiry < apr_time_now() || strcmp(temp_session->op_id, op_id) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: Invalid or expired temporary session");
        return HTTP_FORBIDDEN;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC redirect identified and verified OP: %s", op_id);
    struct oidfed_trust_resolver resolver = oidfedTrustResolverCreate(r, (char*)op_id, rt->trust_anchors, rt->trust_anchors_sz);
    struct oidfed_trust_chains chains = oidfedTrustResolverResolveToValidChains(r, resolver);

    if (oidfedTrustChainsCount(r, chains) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: No valid trust chains found for OP: %s", op_id);
        oidfedTrustChainsDestroy(r, &chains);
        oidfedTrustResolverDestroy(r, &resolver);
        return HTTP_FORBIDDEN;
    }

    struct oidfed_trust_chain chain = oidfedTrustChainsGet(r, chains, 0);
    int errc = 0;
    struct oidfed_metadata metadata = oidfedTrustChainGetMetadata(r, chain, &errc);

    if (errc != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: Failed to get metadata for OP: %s", op_id);
        oidfedTrustChainDestroy(r, &chain);
        oidfedTrustChainsDestroy(r, &chains);
        oidfedTrustResolverDestroy(r, &resolver);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    struct oidfed_openid_provider_metadata op_metadata = oidfedMetadataGetOPMetadata(r, metadata);
    if (op_metadata.impl == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: No OP metadata for OP: %s", op_id);
        oidfedMetadataDestroy(r, &metadata);
        oidfedTrustChainDestroy(r, &chain);
        oidfedTrustChainsDestroy(r, &chains);
        oidfedTrustResolverDestroy(r, &resolver);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    char* token_endpoint = oidfedOpenIDProviderMetadataGetTokenEndpoint(r, op_metadata);
    if (!token_endpoint) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: No token endpoint found for OP: %s", op_id);
        oidfedOpenIDProviderMetadataDestroy(r, &op_metadata);
        oidfedMetadataDestroy(r, &metadata);
        oidfedTrustChainDestroy(r, &chain);
        oidfedTrustChainsDestroy(r, &chains);
        oidfedTrustResolverDestroy(r, &resolver);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC redirect: Found Token Endpoint: %s", token_endpoint);

    const struct oidfed_request_producer producer = oidfedFederationLeafGetRequestObjectProducer(r, rt->leaf);
    const char* redirect_uri = (config->metadata.rp_redirect_uris_sz > 0) ? config->metadata.rp_redirect_uris[0] : "";

    char* token_response = oidfedRequestProducerExchangeCode(r, producer, token_endpoint, (char*)code, (char*)redirect_uri, &errc);

    if (errc != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: Token exchange failed for OP: %s", op_id);
        free(token_endpoint);
        oidfedOpenIDProviderMetadataDestroy(r, &op_metadata);
        oidfedMetadataDestroy(r, &metadata);
        oidfedTrustChainDestroy(r, &chain);
        oidfedTrustChainsDestroy(r, &chains);
        oidfedTrustResolverDestroy(r, &resolver);
        return HTTP_FORBIDDEN;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC redirect: Successfully retrieved tokens: %s", token_response);

    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char sid_bits[17];
    for (int i = 0; i < 16; i++) {
        sid_bits[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    sid_bits[16] = '\0';
    char* sid = apr_pstrdup(r->server->process->pool, (char*)sid_bits);

    struct oidfed_session* session = apr_pcalloc(r->server->process->pool, sizeof(struct oidfed_session));
    session->sid = sid;
    session->op_id = apr_pstrdup(r->server->process->pool, op_id);
    session->token_response = apr_pstrdup(r->server->process->pool, token_response);
    session->expiry = apr_time_now() + apr_time_from_sec(3600); // 1 hour session for now

    rt->session_storage.set(&rt->session_storage, session);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC redirect: Session created for SID: %s", sid);

    ap_cookie_write(r, OIDFED_SESSION_COOKIE, sid, NULL, apr_time_from_sec(3600), r->headers_out, r->err_headers_out, NULL);

    free(token_response);
    free(token_endpoint);
    oidfedOpenIDProviderMetadataDestroy(r, &op_metadata);
    oidfedMetadataDestroy(r, &metadata);
    oidfedTrustChainDestroy(r, &chain);
    oidfedTrustChainsDestroy(r, &chains);
    oidfedTrustResolverDestroy(r, &resolver);

    ap_set_content_type(r, "text/html");
    ap_rprintf(r, "<html><body><h1>Authentication Successful</h1><p>Received tokens and verified with OP.</p></body></html>");

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

    const char* sid = NULL;
    ap_cookie_read(r, OIDFED_SESSION_COOKIE, &sid, 0);

    if (sid) {
        const struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;
        struct oidfed_session* session = rt->session_storage.get(&rt->session_storage, sid);

        if (session) {
            if (session->expiry > apr_time_now()) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OIDC auth: Valid session found for SID: %s", sid);
                char* user = oidfedExtractSubjectFromTokenResponse(r, session->token_response);
                if (user) {
                    r->user = apr_pstrdup(r->pool, user);
                    free(user);
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC auth: Failed to extract user from token response for SID: %s", sid);
                    r->user = apr_pstrdup(r->pool, "oidc_user");
                }
                return OK;
            }
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC auth: Session expired for SID: %s", sid);
            rt->session_storage.remove(&rt->session_storage, sid);
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OIDC auth: Session not found for SID: %s", sid);
        }
    }

    if (strcmp(r->uri, login_url) == CMP_EQ) {
        return DECLINED;
    }

    r->status = HTTP_MOVED_TEMPORARILY;
    apr_table_set(r->headers_out, "Location", login_url);
    return HTTP_MOVED_TEMPORARILY;
}
