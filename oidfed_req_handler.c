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

#include "utils.h"

#ifdef __GNUC__
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#else
#define UNLIKELY(x) x
#define LIKELY(x) x
#endif

static bool
str_empty(const char* str) {
    return str[0] == '\0';
}

static void
generate_oidc_request_state(request_rec* r,
                            const char* op_id,
                            const char* return_to,
                            const struct oidfed_map request_values) {
    char* state = apr_pstrcat(r->pool,
                              encode_netstringc(r->pool, return_to),
                              encode_netstringc(r->pool, op_id),
                              NULL);
    oidfMapSetString(r, request_values, "state", state);
}

static char*
construct_auth_url(request_rec* r,
                   const struct oidfed_config* config,
                   const struct oidfed_openid_provider_metadata op_metadata,
                   const char* op_id,
                   const char* return_to) {
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

    if (config->metadata.rp_redirect_uris_sz <= 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "RP has no redirect URIs set");
        free(issuer);
        free(auth_endpoint);
        return NULL;
    }

    struct oidfed_map request_values = oidfCreateMap(r);
    char* req_redir = apr_pstrcat(r->pool, config->entity_id, config->metadata.rp_redirect_uris[0], NULL);

    oidfMapSetString(r, request_values, "aud", issuer);
    oidfMapSetString(r, request_values, "redirect_uri", req_redir);
    oidfMapSetString(r, request_values, "response_type", "code");
    oidfMapSetString(r, request_values, "scope", "openid");
    generate_oidc_request_state(r, op_id, return_to, request_values);

    int errc = 0;
    struct oidfed_signed_bytes signed_request = oidfedRequestProducerProduceObject(
        r, producer, request_values, (struct oidfed_jws_headers){0}, NULL, 0, &errc);

    if (errc != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed produce object: %d", errc);
        oidfMapDestroy(r, &request_values);
        free(auth_endpoint);
        return NULL;
    }

    size_t jwt_sz = 0;
    char* jwt = oidfedSignedBytesGetData(r, signed_request, &jwt_sz);

    char* final_url = apr_pstrcat(r->pool, auth_endpoint, strchr(auth_endpoint, '?') ? "&" : "?",
                                  "client_id=", apr_pescape_urlencoded(r->pool, config->entity_id),
                                  "&request=", jwt,
                                  "&response_type=code",
                                  "&redirect_uri=", apr_pescape_urlencoded(r->pool, req_redir),
                                  "&scope=openid",
                                  NULL);

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
handle_open_id_authentication(request_rec* r, const struct oidfed_config* config) {
    apr_table_t* args = NULL;
    ap_args_to_table(r, &args);
    if (!args) return req_login_ui_handler(config, r);

    const char* op_id = apr_table_get(args, "iss");
    if (!op_id) return req_login_ui_handler(config, r);

    const char* return_to = apr_table_get(args, "target_link_uri");
    if (!return_to) return_to = "/";

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Initiating login for OP: %s", op_id);
    const struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;
    struct oidfed_trust_resolver resolver = oidfedTrustResolverCreate(
        r, (char*)op_id, rt->trust_anchors, rt->trust_anchors_sz);
    struct oidfed_trust_chains chains = oidfedTrustResolverResolveToValidChains(r, resolver);

    if (oidfedTrustChainsCount(r, chains) <= 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No valid trust chains found for OP: %s", op_id);
        goto cleanup_resolver;
    }

    struct oidfed_trust_chain chain = oidfedTrustChainsGet(r, chains, 0);
    int errc = 0;
    struct oidfed_metadata metadata = oidfedTrustChainGetMetadata(r, chain, &errc);

    if (errc != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to get metadata from trust chain for OP: %s, error: %d", op_id, errc);
        goto cleanup_chain;
    }

    struct oidfed_openid_provider_metadata op_metadata = oidfedMetadataGetOPMetadata(r, metadata);
    if (op_metadata.impl == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to get OP metadata for OP: %s", op_id);
        goto cleanup_metadata;
    }

    char* auth_url = construct_auth_url(r, config, op_metadata, op_id, return_to);
    if (!auth_url) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to construct auth URL for OP: %s", op_id);
        goto cleanup_op_metadata;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Redirecting to OP auth URL: %s", auth_url);

    apr_table_set(r->headers_out, "Location", auth_url);

    oidfedOpenIDProviderMetadataDestroy(r, &op_metadata);
    oidfedMetadataDestroy(r, &metadata);
    oidfedTrustChainDestroy(r, &chain);
    oidfedTrustChainsDestroy(r, &chains);
    oidfedTrustResolverDestroy(r, &resolver);

    return HTTP_MOVED_TEMPORARILY;

cleanup_op_metadata:
    oidfedOpenIDProviderMetadataDestroy(r, &op_metadata);
cleanup_metadata:
    oidfedMetadataDestroy(r, &metadata);
cleanup_chain:
    oidfedTrustChainDestroy(r, &chain);
cleanup_resolver:
    oidfedTrustChainsDestroy(r, &chains);
    oidfedTrustResolverDestroy(r, &resolver);

    return HTTP_INTERNAL_SERVER_ERROR;
}

int
oidfed_req_handler(request_rec* r) {
    if (strcmp(r->handler, "oidfed") != CMP_EQ) return DECLINED;
    if (!r->uri) return DECLINED;

    const struct oidfed_config* config = ap_get_module_config(r->server->module_config,
                                                              &oidfed);
    assert(config->worker_cfg.runtime->owner_pid == getpid() && "mismatched owner pid");

    /// XXX - replace this with a hashmap

    /**** /.well-known/openid-federation ****/
    if (strcmp(r->uri, OIDFED_WELL_KNOWN_PATH) == CMP_EQ) return req_well_known_handler(config, r);

    /**** /login ****/
    if (strcmp(r->uri, config->login_url) == CMP_EQ) return handle_open_id_authentication(r, config);

    /**** REDIRECT URI ****/
    for (size_t i = 0; i < config->metadata.rp_redirect_uris_sz; i++) {
        if (strcmp(r->uri, config->metadata.rp_redirect_uris[i]) == CMP_EQ) {
            return req_redirect_handler(config, r);
        }
    }

    return HTTP_NOT_FOUND;
}

struct op_info {
    char* entity_id;
    char* display_name;
};

static int
compare_ops(const void* a, const void* b) {
    const struct op_info* op_a = (const struct op_info*) a;
    const struct op_info* op_b = (const struct op_info*) b;

    const char* name_a = op_a->display_name ? op_a->display_name : op_a->entity_id;
    const char* name_b = op_b->display_name ? op_b->display_name : op_b->entity_id;

    return strcmp(name_a, name_b);
}

static void
extract_entity_info(request_rec* r,
                    apr_array_header_t* ops_list,
                    const struct oidfed_collected_entity entity) {
    struct op_info* info = apr_array_push(ops_list);
    info->entity_id = apr_pstrdup(r->pool, entity.entity_id);
    info->display_name = NULL;

    struct oidfed_collected_entity_ui_enumerator enumerator =
            oidfedCollectedEntityEnumerateUi(r, entity);
    while (oidfedCollectedEntityNextUi(r, &enumerator)) {
        struct oidfed_ui_info ui = oidfedCollectedEntityGetUiValue(r, &enumerator);
        if (ui.display_name) info->display_name = apr_pstrdup(r->pool, ui.display_name);
        oidfedUiInfoDestroy(r, &ui);
    }
    oidfedCollectedEntityFinishUi(r, &enumerator);
}

static void
collect_from_trust_anchor(request_rec* r,
                          struct oidfed_worker_runtime* rt,
                          apr_hash_t* rendered_ops,
                          apr_array_header_t* ops_list,
                          const struct oidfed_trust_anchor trust_anchor) {
    struct oidfed_collected_entity* entities = NULL;
    size_t entities_sz = 0;
    oidfedCollectorCollectVerifiedEntitiesWithFilter(r, trust_anchor,
                                                     &rt->collector,
                                                     rt->filter,
                                                     &entities,
                                                     &entities_sz);

    for (size_t i = 0; i < entities_sz; i++) {
        if (apr_hash_get(rendered_ops, entities[i].entity_id, APR_HASH_KEY_STRING)) continue;

        apr_hash_set(rendered_ops, entities[i].entity_id, APR_HASH_KEY_STRING, entities[i].entity_id);
        extract_entity_info(r, ops_list, entities[i]);
    }

    for (size_t i = 0; i < entities_sz; i++)
        oidfedCollectedEntityDestroy(r, &entities[i]);
    free(entities);
}

int
req_login_ui_handler(const struct oidfed_config* config, request_rec* r) {
    struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;
    apr_hash_t* rendered_ops = apr_hash_make(r->pool);
    apr_array_header_t* ops_list = apr_array_make(r->pool, 10, sizeof(struct op_info));

    apr_table_t* args = NULL;
    ap_args_to_table(r, &args);

    const char* return_to = NULL;
    if (args) {
        return_to = apr_table_get(args, "target_link_uri");
    }

    const char* op_hint = apr_table_get(args, "hint");
    if (op_hint) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OP hint: %s", op_hint);
    }

    const char* rp_id = apr_table_get(args, "entity_id");
    if (!rp_id) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Home discovery: No entity_id received from RP");
        return HTTP_BAD_REQUEST;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Collecting OPs from %lu trust anchors",
                  rt->trust_anchors_sz);

    for (size_t i = 0; i < rt->trust_anchors_sz; i++)
        collect_from_trust_anchor(r, rt, rendered_ops, ops_list, rt->trust_anchors[i]);

    struct op_info hinted = {0};
    int hinted_idx = 0;
    
    qsort(ops_list->elts, ops_list->nelts, ops_list->elt_size, compare_ops);
    for (; hinted_idx < ops_list->nelts; hinted_idx++) {
        const struct op_info* const info = &APR_ARRAY_IDX(ops_list, hinted_idx, struct op_info);
        if (op_hint && strcmp(info->entity_id, op_hint) == CMP_EQ) {
            hinted = *info;
            break;
        }
    }

    ap_set_content_type(r, "text/html");
    ap_rputs("<html>"
             "<head>"
             "<title>Apache OpenId Federation</title>"
             "<link rel=\"stylesheet\" type=\"text/css\" href=\"oidfed.css\">"
             "</head>"
             "<body>"
             "<h1 class=\"op-listing-header\">Choose where to log in:</h1>", r);

    if (hinted.entity_id) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OP hinted: %s (%s)",
            hinted.entity_id,
            hinted.display_name ? hinted.display_name : "?");
        char* name = hinted.display_name;
        if (!name) name = hinted.entity_id;
        if (str_empty(name)) name = hinted.entity_id;

        ap_rputs("<h2 class=\"op-listing-header\">Suggested:</h2>", r);
        ap_rputs("<div class=\"op-elem op-hinted\" style=\"--op-index: 0\"><a href=\"", r);
        ap_rputs(config->login_url, r);
        ap_rputs("?iss=", r);
        ap_rputs(apr_pescape_urlencoded(r->pool, hinted.entity_id), r);
        if (return_to) {
            ap_rputs("&target_link_uri=", r);
            ap_rputs(apr_pescape_urlencoded(r->pool, return_to), r);
        }
        ap_rputs("\">", r);
        ap_rputs(name, r);
        ap_rputs("</a></div>", r);
    }
    
    ap_rputs("<h2 class=\"op-listing-header\">Listing:</h2>", r);
    ap_rputs("<ul class=\"op-listing\">", r);
    for (int i = 0; i < ops_list->nelts; i++) {
        if (i == hinted_idx) continue;

        char i_str[sizeof("18446744073709551615")] = {0};
        assert(sizeof(int) * CHAR_BIT <= 64); // error on massive int sizes

        const struct op_info* const info = &APR_ARRAY_IDX(ops_list, i, struct op_info);
        const size_t i_str_sz = si_fmt(i_str, i, 10);
        i_str[i_str_sz] = '\0';

        char* name = info->display_name;
        if (!name) name = info->entity_id;
        if (str_empty(name)) name = info->entity_id;

        ap_rputs("<li class=\"op-elem\" style=\"--op-index: ", r);
        ap_rputs(i_str, r);
        ap_rputs("\"><a href=\"", r);
        ap_rputs(config->login_url, r);
        ap_rputs("?iss=", r);
        ap_rputs(apr_pescape_urlencoded(r->pool, info->entity_id), r);
        if (return_to) {
            ap_rputs("&target_link_uri=", r);
            ap_rputs(apr_pescape_urlencoded(r->pool, return_to), r);
        }
        ap_rputs("\">", r);
        ap_rputs(name, r);
        ap_rputs("</a></li>", r);
    }

    ap_rputs("</ul></body></html>", r);
    return OK;
}

int
req_well_known_handler(const struct oidfed_config* config, request_rec* r) {
    const struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;

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

    char* state = apr_pstrdup(r->pool, apr_table_get(args, "state"));
    const char* code = apr_table_get(args, "code");
    const char* error = apr_table_get(args, "error");
    const char* error_description = apr_table_get(args, "error_description");

    if (error) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect error: %s (%s)", error,
                      error_description ? error_description : "no description");
        return HTTP_FORBIDDEN;
    }

    if (!code || !state) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: Missing code or state");
        return HTTP_BAD_REQUEST;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OIDC redirect received code and state: state=%s", state);
    const struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;

    const char* sid_from_cookie = NULL;
    ap_cookie_read(r, OIDFED_SESSION_COOKIE, &sid_from_cookie, 0);
    if (sid_from_cookie) rt->session_storage.remove(&rt->session_storage, sid_from_cookie);

    // Retrieve OP identifier from state.
    char* next_value = NULL;
    char* return_to = decode_netstring_inplace(state, &next_value);
    char* op_id = decode_netstring_inplace(next_value + 1, &next_value);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OIDC redirect: return_to=%s, op_id=%s",
                  return_to, op_id);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC redirect identified and verified OP: %s", op_id);
    struct oidfed_trust_resolver resolver = oidfedTrustResolverCreate(r, (char*)op_id, rt->trust_anchors,
                                                                      rt->trust_anchors_sz);
    struct oidfed_trust_chains chains = oidfedTrustResolverResolveToValidChains(r, resolver);

    int errc = 0;
    if (oidfedTrustChainsCount(r, chains) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: No valid trust chains found for OP: %s", op_id);
        goto cleanup_resolver;
    }

    struct oidfed_trust_chain chain = oidfedTrustChainsGet(r, chains, 0);
    struct oidfed_metadata metadata = oidfedTrustChainGetMetadata(r, chain, &errc);

    if (errc != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: Failed to get metadata for OP: %s", op_id);
        goto cleanup_chain;
    }

    struct oidfed_openid_provider_metadata op_metadata = oidfedMetadataGetOPMetadata(r, metadata);
    if (op_metadata.impl == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: No OP metadata for OP: %s", op_id);
        goto cleanup_metadata;
    }

    char* token_endpoint = oidfedOpenIDProviderMetadataGetTokenEndpoint(r, op_metadata);
    if (!token_endpoint) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: No token endpoint found for OP: %s", op_id);
        goto cleanup_op_metadata;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC redirect: Found Token Endpoint: %s", token_endpoint);

    const struct oidfed_request_producer producer = oidfedFederationLeafGetRequestObjectProducer(r, rt->leaf);
    const char* redirect_uri = (config->metadata.rp_redirect_uris_sz > 0) ? config->metadata.rp_redirect_uris[0] : "";

    char* token_response = oidfedRequestProducerExchangeCode(r, producer, token_endpoint, (char*)code,
                                                             (char*)redirect_uri, &errc);
    if (errc != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC redirect: Token exchange failed for OP: %s", op_id);
        goto cleanup_token;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC redirect: Successfully retrieved tokens: %s", token_response);

    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    char sid_bits[17] = {0};
    apr_generate_random_bytes((unsigned char*) sid_bits, sizeof(sid_bits) - 1);
    for (int i = 0; i < sizeof(sid_bits) - 1; i++) sid_bits[i] = charset[sid_bits[i] % (sizeof(charset) - 1)];
    char* sid = apr_pstrdup(r->server->process->pool, sid_bits);

    struct oidfed_session* session = apr_pcalloc(r->server->process->pool, sizeof(struct oidfed_session));
    session->sid = sid;
    session->op_id = apr_pstrdup(r->server->process->pool, op_id);
    session->token_response = apr_pstrdup(r->server->process->pool, token_response);
    session->expiry = apr_time_now() + apr_time_from_sec(3600);

    rt->session_storage.set(&rt->session_storage, session);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC redirect: Session created for SID: %s", sid);

    ap_cookie_write(r, OIDFED_SESSION_COOKIE, sid, NULL, apr_time_from_sec(3600), r->headers_out, r->err_headers_out,
                    NULL);

    apr_table_add(r->headers_out, "Location", return_to);

    free(token_response);
    free(token_endpoint);
    oidfedOpenIDProviderMetadataDestroy(r, &op_metadata);
    oidfedMetadataDestroy(r, &metadata);
    oidfedTrustChainDestroy(r, &chain);
    oidfedTrustChainsDestroy(r, &chains);
    oidfedTrustResolverDestroy(r, &resolver);

    return HTTP_MOVED_TEMPORARILY;

cleanup_token:
    free(token_response);
    free(token_endpoint);
cleanup_op_metadata:
    oidfedOpenIDProviderMetadataDestroy(r, &op_metadata);
cleanup_metadata:
    oidfedMetadataDestroy(r, &metadata);
cleanup_chain:
    oidfedTrustChainDestroy(r, &chain);
cleanup_resolver:
    oidfedTrustChainsDestroy(r, &chains);
    oidfedTrustResolverDestroy(r, &resolver);

    return (errc != 0) ? HTTP_FORBIDDEN : HTTP_INTERNAL_SERVER_ERROR;
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

    if (!sid) goto check_login_url;

    const struct oidfed_worker_runtime* rt = config->worker_cfg.runtime;
    struct oidfed_session* session = rt->session_storage.get(&rt->session_storage, sid);

    if (!session) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OIDC auth: Session not found for SID: %s", sid);
        goto check_login_url;
    }

    if (session->expiry <= apr_time_now()) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "OIDC auth: Session expired for SID: %s", sid);
        rt->session_storage.remove(&rt->session_storage, sid);
        goto check_login_url;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OIDC auth: Valid session found for SID: %s", sid);
    char* user = oidfedExtractSubjectFromTokenResponse(r, session->token_response);
    if (user) {
        r->user = apr_pstrdup(r->pool, user);
        free(user);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC auth: Failed to extract user from token response for SID: %s",
                      sid);
        r->user = apr_pstrdup(r->pool, "oidc_user");
    }
    return OK;

check_login_url:
    if (strcmp(r->uri, login_url) == CMP_EQ) {
        return DECLINED;
    }

    struct oidfed_config* const cfg = ap_get_module_config(r->server->module_config, &oidfed);
    if (UNLIKELY(!cfg)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "OIDC auth: module configuration vanished from httpd");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    const char* entity_id = cfg->entity_id;

    const char* home_hint = cfg->home_discovery_op_hint;
    if (str_empty(home_hint)) home_hint = 0;

    const char* final_url = apr_pstrcat(r->pool, login_url, strchr(login_url, '?') ? "&" : "?",
                                        "entity_id=", apr_pescape_urlencoded(r->pool, entity_id),
                                        "&target_link_uri=", apr_pescape_urlencoded(r->pool, r->unparsed_uri),
                                        home_hint ? "&hint=" : NULL,
                                        home_hint ? apr_pescape_urlencoded(r->pool, home_hint) : NULL,
                                        NULL);
    apr_table_set(r->headers_out, "Location", final_url);
    return HTTP_MOVED_TEMPORARILY;
}
