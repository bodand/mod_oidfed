#ifndef OIDFED_CONFIG_H
#define OIDFED_CONFIG_H

#include <ap_config.h>
#include <httpd.h>
#include <http_config.h>
#include <stddef.h>

#include <oidfed_wrap_loader.h>

// COMPILE TIME CONFIGURATION //

#define CONFIG_TRUST_ANCHORS_MAX 100
#define CONFIG_AUTHORITY_HINTS_MAX 100
#define CONFIG_LOGIN_URL_SIZE_MAX 256
#define CONFIG_ENTITY_ID_MAX 1024
#define CONFIG_FILTER_TYPE_MAX 64

// Default configuration values //
// Warning: They are initialized without length checks. Setting longer defaults
// than the maximum sizes configured above, the behavior of httpd is undefined.

#define CONFIG_DEFAULT_LAZY_LOAD_SYMBOLS true
#define CONFIG_DEFAULT_ENTITY_ID "badly-configured-entity"
#define CONFIG_DEFAULT_FEDERATION_KEY_FILE "./federation.key"
#define CONFIG_DEFAULT_LOGIN_PATH "/login"

#define OIDFED_WELL_KNOWN_PATH "/.well-known/openid-federation"

// RUNTIME CONFIGURATION //

struct oidfed_worker_runtime {
    /// Worker PID that created and owns this runtime
    pid_t owner_pid;
    /// The server object that created this runtime
    server_rec* server;

    /// The array of wrapper trust anchor entities
    struct oidfed_trust_anchor* trust_anchors;
    size_t trust_anchors_sz;

    /// Entity collection filter for looking up OP-s
    struct oidfed_collection_filter filter;

    /// Entity collector based on the above trust anchors
    struct oidfed_collector collector;
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
    /// Trust anchors accepted by given entity
    char* trust_anchors[CONFIG_TRUST_ANCHORS_MAX];
    size_t trust_anchors_sz;
    /// OP Filters
    struct oidfed_filter_config* filters;
    /// Key file to sign federation JWT-s with
    char federation_signing_key_file[APR_PATH_MAX];
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
oidfed_cfg_fed_singing_key(cmd_parms* parms, void* cfg, const char* key_file);

const char*
oidfed_cfg_set_entity_id(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_cfg_add_authority_hint(cmd_parms* parms, void* mconfig, const char* w);

const char*
oidfed_add_op_filter_chain(cmd_parms* parms, void* mconfig, int argc, char* const argv[]);

// APACHE //

extern module AP_MODULE_DECLARE_DATA oidfed_module;

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
    AP_INIT_TAKE1("OidfedFederationSigningKeyFile", oidfed_cfg_fed_singing_key, NULL, RSRC_CONF,
                  "The private key with which to sign federation data"),
    AP_INIT_TAKE_ARGV("OidfedAddOpFilterChain", oidfed_add_op_filter_chain, NULL, RSRC_CONF,
                      "Adds filter to the OP filter chain"),
    {NULL}
};

#define CMP_EQ 0

#endif
