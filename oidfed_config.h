#ifndef OIDFED_CONFIG_H
#define OIDFED_CONFIG_H

#include <ap_config.h>
#include <httpd.h>
#include <http_config.h>
#include <stddef.h>

#include <apr_hash.h>
#include <apr_thread_mutex.h>
#include <oidfed_wrap_loader.h>
#include <oidfed_req_handler.h>

// COMPILE TIME CONFIGURATION //

#define CONFIG_TRUST_ANCHORS_MAX 100
#define CONFIG_AUTHORITY_HINTS_MAX 100
#define CONFIG_LOGIN_URL_SIZE_MAX 256
#define CONFIG_ENTITY_ID_MAX 1024
#define CONFIG_FILTER_TYPE_MAX 64
#define CONFIG_SIGNALG_MAX 6
#define CONFIG_METADATA_STR_MAX 128
#define CONFIG_METADATA_ARRAY_MAX 100

// Default configuration values //
// Warning: They are initialized without length checks. Setting longer defaults
// than the maximum sizes configured above, the behavior of httpd is undefined.

#define CONFIG_DEFAULT_LAZY_LOAD_SYMBOLS true
#define CONFIG_DEFAULT_ENTITY_ID "badly-configured-entity"
#define CONFIG_DEFAULT_FEDERATION_KEY_FILE "./federation.key"
#define CONFIG_DEFAULT_OIDC_KEY_FILE "./oidc.key"
#define CONFIG_DEFAULT_LOGIN_PATH "/login"
#define CONFIG_DEFAULT_FED_SIGNALG "ES512"
#define CONFIG_DEFAULT_OIDC_SIGNALG "ES512"

#define CONFIG_DEFAULT_METADATA_URL ""
#define CONFIG_DEFAULT_METADATA_DIGEST ""
#define CONFIG_DEFAULT_METADATA_DIGEST_ALG "sha256"

#define OIDFED_WELL_KNOWN_PATH "/.well-known/openid-federation"

// RUNTIME CONFIGURATION //

struct oidfed_worker_runtime {
    /// Worker PID that created and owns this runtime
    pid_t owner_pid;
    /// The server object that created this runtime
    server_rec* server;

    /// Relying party metadata
    struct oidfed_metadata rp_metadata;
    /// Federation Leaf entity
    struct oidfed_federation_leaf leaf;

    /// The array of wrapper trust anchor entities
    struct oidfed_trust_anchor* trust_anchors;
    size_t trust_anchors_sz;

    /// Entity collection filter for looking up OP-s
    struct oidfed_collection_filter filter;

    /// Entity collector based on the above trust anchors
    struct oidfed_collector collector;

    /// Signer object for OID Federation signing
    struct oidfed_versatile_signer federation_signer;
    /// Key storage for OID Federation signing
    struct oidfed_single_key_storage federation_key_storage;
    /// Signature algorithm for OID Federation signing
    struct oidfed_signature_algorithm federation_signing_alg;

    /// Signer object for OID Connect signing
    struct oidfed_versatile_signer oidc_signer;
    /// Key storage for OID Connect signing
    struct oidfed_single_key_storage oidc_key_storage;
    /// Signature algorithm for OID Connect signing
    struct oidfed_signature_algorithm oidc_signing_alg;

    /// Session storage
    struct oidfed_session_storage session_storage;
};

struct oidfed_filter_config {
    /// Type of the filter to enact:
    ///  - op -> filter any OPs under a trust anchor
    ///  - explicit -> filter OPs under a trust anchor with explicit registration
    ///  - auto -> filter OPs under a trust anchor with automatic registration
    ///  - scope -> filter OPs supporting *arguments* scopes
    ///  - grant -> filter OPs support *arguments* grants
    char type[CONFIG_FILTER_TYPE_MAX];

    /// The set of arguments passed to the filter algorithm. Used by scope and
    /// grant, NULL for others.
    char** arguments;
    size_t arguments_sz;

    struct oidfed_filter_config* next;
};

struct oidfed_worker_config {
    /// A pointer storing worker-specific runtime data
    struct oidfed_worker_runtime* runtime;
    /// Whether to only load symbols lazily from the wrap library
    bool lazy_load_symbols;
};

struct oidfed_metadata_config {
    /// RP Metadata URL
    char rp_metadata_url[CONFIG_METADATA_STR_MAX];
    /// RP Metadata Digest
    char rp_metadata_digest[CONFIG_METADATA_STR_MAX];
    /// RP Metadata Digest Algorithm
    char rp_metadata_digest_alg[CONFIG_METADATA_STR_MAX];

    /// Federation Entity Metadata URL
    char fe_metadata_url[CONFIG_METADATA_STR_MAX];
    /// Federation Entity Metadata Digest
    char fe_metadata_digest[CONFIG_METADATA_STR_MAX];
    /// Federation Entity Metadata Digest Algorithm
    char fe_metadata_digest_alg[CONFIG_METADATA_STR_MAX];

    /// RP Redirect URIs
    char* rp_redirect_uris[CONFIG_METADATA_ARRAY_MAX];
    size_t rp_redirect_uris_sz;
};

struct oidfed_config {
    /* Module specific configuration */
    /// Path of the URL where the user can select where to log in
    char login_url[CONFIG_LOGIN_URL_SIZE_MAX];
    /// Nested config for worker-specific configs
    struct oidfed_worker_config worker_cfg;

    /* OpenID Federation configuration */
    /// Entity ID of the entity in the federation
    char entity_id[CONFIG_ENTITY_ID_MAX];

    /// Authority hints of the entity
    char* authority_hints[CONFIG_AUTHORITY_HINTS_MAX];
    size_t authority_hints_sz;

    /// Trust anchors accepted by this entity
    char* trust_anchors[CONFIG_TRUST_ANCHORS_MAX];
    size_t trust_anchors_sz;

    /// OP Filters (linked list)
    struct oidfed_filter_config* filters;

    /// Key file to sign federation metadata with
    char federation_signing_key_file[APR_PATH_MAX];
    /// Signature algorithm to use for federation metadata signing
    char federation_signing_alg[CONFIG_SIGNALG_MAX];

    /// Key file to sign replying-party metadata with
    char oidc_signing_key_file[APR_PATH_MAX];
    /// Signature algorithm to use for replying-party metadata signing
    char oidc_signing_alg[CONFIG_SIGNALG_MAX];

    /// Nested metadata configuration
    struct oidfed_metadata_config metadata;
};

void
oidfed_worker_runtime_init(server_rec* sv, struct oidfed_config* config);

void
oidfed_worker_config_init(struct oidfed_worker_config* cfg);

void
oidfed_config_init(struct oidfed_config* cfg);

const char*
oidfed_cfg_add_trust_anchor(cmd_parms* cmd, void* cfg, const char* entity_id);

const char*
oidfed_cfg_wrap_lazy(cmd_parms* parms, void* mconfig, int on);

const char*
oidfed_cfg_login_url(cmd_parms* cmd, void* cfg, const char* url);

const char*
oidfed_cfg_set_entity_id(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_cfg_add_authority_hint(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_add_op_filter_chain(cmd_parms* parms, void* mconfig, int argc, char* const argv[]);

const char*
oidfed_cfg_set_fed_private_key(cmd_parms* parms, void* cfg, const char* key_file);

const char*
oidfed_cfg_set_oidc_private_key(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfged_cfg_set_oidc_signalg(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfged_cfg_set_fed_signalg(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_cfg_set_rp_metadata_url(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_cfg_set_rp_metadata_digest(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_cfg_set_rp_metadata_digest_alg(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_cfg_set_fe_metadata_url(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_cfg_set_fe_metadata_digest(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_cfg_set_fe_metadata_digest_alg(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_cfg_add_rp_redirect_uri(cmd_parms* parms, void* mconfig, const char* w);

// APACHE //

extern module AP_MODULE_DECLARE_DATA oidfed;

static const command_rec oidfed_cmds[] = {
    AP_INIT_TAKE1("OidfedSetEntityId", oidfed_cfg_set_entity_id, NULL, RSRC_CONF,
                  "Set entity id of the federation entity"),
    AP_INIT_TAKE1("OidfedAddTrustAnchor", oidfed_cfg_add_trust_anchor, NULL, RSRC_CONF,
                  "Add given trust anchor to federation"),
    AP_INIT_TAKE1("OidfedAddAuthorityHint", oidfed_cfg_add_authority_hint, NULL, RSRC_CONF,
                  "Add authority hint to federation entity metadata"),
    AP_INIT_TAKE1("OidfedSetLoginPath", oidfed_cfg_login_url, NULL, RSRC_CONF,
                  "Sets the path to redirect the user to when logging in"),
    AP_INIT_FLAG("OidfedWrapperLazyLoadSymbols", oidfed_cfg_wrap_lazy, NULL, RSRC_CONF,
                 "Lazily load symbols when loading the wrap library"),
    AP_INIT_TAKE_ARGV("OidfedAddOpFilterChain", oidfed_add_op_filter_chain, NULL, RSRC_CONF,
                      "Adds filter to the OP filter chain"),
    AP_INIT_TAKE1("OidfedSetOidConnectSigningKey", oidfed_cfg_set_oidc_private_key, NULL, RSRC_CONF,
                  "Set the RelyingParty metadata signing key"),
    AP_INIT_TAKE1("OidfedSetOidConnectSignatureAlgorithm", oidfged_cfg_set_oidc_signalg, NULL, RSRC_CONF,
                  "Set the RelyingParty metadata signature algorithm"),
    AP_INIT_TAKE1("OidfedSetOidFederationSigningKey", oidfed_cfg_set_fed_private_key, NULL, RSRC_CONF,
                  "Set the Federation metadata signing key"),
    AP_INIT_TAKE1("OidfedSetOidFederationSignatureAlgorithm", oidfged_cfg_set_fed_signalg, NULL, RSRC_CONF,
                  "Set the RelyingParty metadata signature algorithm"),
    AP_INIT_TAKE1("OidfedSetRPMetadataURL", oidfed_cfg_set_rp_metadata_url, NULL, RSRC_CONF,
                  "Set the Relying Party Metadata URL"),
    AP_INIT_TAKE1("OidfedSetRPMetadataDigest", oidfed_cfg_set_rp_metadata_digest, NULL, RSRC_CONF,
                  "Set the Relying Party Metadata Digest"),
    AP_INIT_TAKE1("OidfedSetRPMetadataDigestAlgorithm", oidfed_cfg_set_rp_metadata_digest_alg, NULL, RSRC_CONF,
                  "Set the Relying Party Metadata Digest Algorithm"),
    AP_INIT_TAKE1("OidfedSetFEMetadataURL", oidfed_cfg_set_fe_metadata_url, NULL, RSRC_CONF,
                  "Set the Federation Entity Metadata URL"),
    AP_INIT_TAKE1("OidfedSetFEMetadataDigest", oidfed_cfg_set_fe_metadata_digest, NULL, RSRC_CONF,
                  "Set the Federation Entity Metadata Digest"),
    AP_INIT_TAKE1("OidfedSetFEMetadataDigestAlgorithm", oidfed_cfg_set_fe_metadata_digest_alg, NULL, RSRC_CONF,
                  "Set the Federation Entity Metadata Digest Algorithm"),
    AP_INIT_TAKE1("OidfedAddRPRedirectURI", oidfed_cfg_add_rp_redirect_uri, NULL, RSRC_CONF,
                  "Add a redirect URI to the Relying Party metadata"),
    {NULL}
};

#define CMP_EQ 0

#endif
