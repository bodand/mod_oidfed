#include <ap_config.h>
#include <httpd.h>
#include <http_log.h>

#include <assert.h>
#include <dlfcn.h>

#include <oidfed_wrap_loader.h>
#include <oidfed_config.h>

#define OIDFED_FN_HOLDER_PREFIX OIFFn_

#ifdef __GNUC__
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#else
#define UNLIKELY(x) x
#define LIKELY(x) x
#endif

#define OIDFED_WORKER_DYNLIB_PATH "liboidfed_wrap.so"
#define OIDFED_WORKER_DYNLIB_HANDLE "OIDFED.WORKER.WRAPPER_DYNLIB"

#define OIDFED_CAT_I(x, y) x##y
#define OIDFED_CAT(x, y) OIDFED_CAT_I(x, y)

#define OIDFED_MAYLOAD_COMMON(fn, datapool, logger, ...) \
    do { \
        if (LIKELY(OIDFED_CAT(OIDFED_FN_HOLDER_PREFIX, fn))) break; \
        void* dynlib = NULL; \
        apr_pool_userdata_get(&dynlib, OIDFED_WORKER_DYNLIB_HANDLE, datapool); \
        if (UNLIKELY(dynlib == NULL)) { \
            logger(APLOG_MARK, APLOG_EMERG, __VA_ARGS__, "oidfedWrap called without initialization!"); \
            assert(false && "module invariant broken: oidfed_worker_init() not called"); \
        } \
        void* sym = dlsym(dynlib, APR_STRINGIFY(fn)); \
        if (UNLIKELY(!sym)) { \
            logger(APLOG_MARK, APLOG_EMERG, __VA_ARGS__, \
                "oidfedWrap: symbol '%s' is not found in wrap library.", \
                APR_STRINGIFY(fn)); \
            assert(false && "module invariant broken: incompatible wrap library found"); \
        } \
        OIDFED_CAT(OIDFED_FN_HOLDER_PREFIX, fn) = sym;\
    } while (0)

#define OIDFED_MAYLOAD_ON_INIT(sv, fn) \
    OIDFED_MAYLOAD_COMMON(fn, sv->process->pconf, ap_log_perror, 0, sv->process->pconf)
#define OIDFED_MAYLOAD_FOR_REQUEST(r, fn) \
    OIDFED_MAYLOAD_COMMON(fn, r->server->process->pconf, ap_log_rerror, 0, r)

#define OIDFED_MAYLOAD_REQUEST(ret, fn) \
    OIDFED_MAYLOAD_FOR_REQUEST(r, fn); \
    ret OIDFED_CAT(OIDFED_FN_HOLDER_PREFIX, fn)

#define OIDFED_MAYLOAD_SERVER(ret, fn) \
    OIDFED_MAYLOAD_ON_INIT(sv, fn); \
    ret OIDFED_CAT(OIDFED_FN_HOLDER_PREFIX, fn)

static apr_status_t
oidfed_worker_deinit_dynlib(void* data) {
    dlclose(data);
    return APR_SUCCESS;
}

apr_status_t
oidfed_worker_init(const struct oidfed_worker_config* cfg, apr_pool_t* p) {
    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, p, "oidfedWrap: loading wrap library: %s",
                  OIDFED_WORKER_DYNLIB_PATH);
    const void* dl = dlopen(OIDFED_WORKER_DYNLIB_PATH,
                            (cfg->lazy_load_symbols ? RTLD_LAZY : RTLD_NOW)
                            | RTLD_LOCAL);
    if (!dl) {
        ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, p, "oidfedWrap: failed to load wrap library: %s: %s",
                      OIDFED_WORKER_DYNLIB_PATH,
                      dlerror());
        return APR_ENOENT;
    }
    return apr_pool_userdata_set(dl, OIDFED_WORKER_DYNLIB_HANDLE, oidfed_worker_deinit_dynlib, p);
}

static void (*OIFFn_oidfedCollectedEntityDestroy)(struct oidfed_collected_entity* ce) = 0;

void
OIFMayLoad_oidfedCollectedEntityDestroy(request_rec* r, struct oidfed_collected_entity* ce) {
    OIDFED_MAYLOAD_REQUEST(, oidfedCollectedEntityDestroy)(ce);
}

void
OIFMayLoad_oidfedCollectedEntityDestroy_server(server_rec* sv, struct oidfed_collected_entity* ce) {
    OIDFED_MAYLOAD_SERVER(, oidfedCollectedEntityDestroy)(ce);
}

static struct oidfed_collected_entity_ui_enumerator (*OIFFn_oidfedCollectedEntityEnumerateUi)(
    struct oidfed_collected_entity ce) = 0;

struct oidfed_collected_entity_ui_enumerator
OIFMayLoad_oidfedCollectedEntityEnumerateUi(request_rec* r,
                                            struct oidfed_collected_entity ce) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedCollectedEntityEnumerateUi)(ce);
}

struct oidfed_collected_entity_ui_enumerator
OIFMayLoad_oidfedCollectedEntityEnumerateUi_server(server_rec* sv,
                                            struct oidfed_collected_entity ce) {
    OIDFED_MAYLOAD_SERVER(return, oidfedCollectedEntityEnumerateUi)(ce);
}

static _Bool (*OIFFn_oidfedCollectedEntityNextUi)(struct oidfed_collected_entity_ui_enumerator* enumer) = 0;

_Bool
OIFMayLoad_oidfedCollectedEntityNextUi(request_rec* r,
                                       struct oidfed_collected_entity_ui_enumerator* enumer) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedCollectedEntityNextUi)(enumer);
}

_Bool
OIFMayLoad_oidfedCollectedEntityNextUi_server(server_rec* sv,
                                       struct oidfed_collected_entity_ui_enumerator* enumer) {
    OIDFED_MAYLOAD_SERVER(return, oidfedCollectedEntityNextUi)(enumer);
}

static void (*OIFFn_oidfedCollectedEntityFinishUi)(struct oidfed_collected_entity_ui_enumerator* enumer) = 0;

void
OIFMayLoad_oidfedCollectedEntityFinishUi(request_rec* r,
                                         struct oidfed_collected_entity_ui_enumerator* enumer) {
    OIDFED_MAYLOAD_REQUEST(, oidfedCollectedEntityFinishUi)(enumer);
}

void
OIFMayLoad_oidfedCollectedEntityFinishUi_server(server_rec* sv,
                                         struct oidfed_collected_entity_ui_enumerator* enumer) {
    OIDFED_MAYLOAD_SERVER(, oidfedCollectedEntityFinishUi)(enumer);
}

static struct oidfed_ui_info (*OIFFn_oidfedCollectedEntityGetUiValue)(
    struct oidfed_collected_entity_ui_enumerator* enumer) = 0;

struct oidfed_ui_info
OIFMayLoad_oidfedCollectedEntityGetUiValue(request_rec* r,
                                           struct oidfed_collected_entity_ui_enumerator* enumer) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedCollectedEntityGetUiValue)(enumer);
}

struct oidfed_ui_info
OIFMayLoad_oidfedCollectedEntityGetUiValue_server(server_rec* sv,
                                           struct oidfed_collected_entity_ui_enumerator* enumer) {
    OIDFED_MAYLOAD_SERVER(return, oidfedCollectedEntityGetUiValue)(enumer);
}

static struct oidfed_collection_filter (*OIFFn_oidfedEmptyCollectionFilter)(void) = 0;

struct oidfed_collection_filter
OIFMayLoad_oidfedEmptyCollectionFilter(request_rec* r) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedEmptyCollectionFilter)();
}

struct oidfed_collection_filter
OIFMayLoad_oidfedEmptyCollectionFilter_server(server_rec* sv) {
    OIDFED_MAYLOAD_SERVER(return, oidfedEmptyCollectionFilter)();
}

static void (*OIFFn_oidfedCollectionFilterDestroy)(struct oidfed_collection_filter* cfs) = 0;

void
OIFMayLoad_oidfedCollectionFilterDestroy(request_rec* r,
                                         struct oidfed_collection_filter* cfs) {
    OIDFED_MAYLOAD_REQUEST(, oidfedCollectionFilterDestroy)(cfs);
}

void
OIFMayLoad_oidfedCollectionFilterDestroy_server(server_rec* sv,
                                         struct oidfed_collection_filter* cfs) {
    OIDFED_MAYLOAD_SERVER(, oidfedCollectionFilterDestroy)(cfs);
}

static void (*OIFFn_oidfedCollectionFilterAppend)(struct oidfed_collection_filter* cfs,
                                                  uintptr_t filter) = 0;

void
OIFMayLoad_oidfedCollectionFilterAppend(request_rec* r,
                                        struct oidfed_collection_filter* cfs,
                                        uintptr_t filter) {
    OIDFED_MAYLOAD_REQUEST(, oidfedCollectionFilterAppend)(cfs, filter);
}

void
OIFMayLoad_oidfedCollectionFilterAppend_server(server_rec* sv,
                                        struct oidfed_collection_filter* cfs,
                                        uintptr_t filter) {
    OIDFED_MAYLOAD_SERVER(, oidfedCollectionFilterAppend)(cfs, filter);
}

static uintptr_t (*OIFFn_oidfedEntityCollectionFilterOPSupportsExplicitRegistration)(
    char** taIds,
    size_t taIdsCount) = 0;

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPSupportsExplicitRegistration(request_rec* r,
                                                                      char** taIds,
                                                                      size_t taIdsCount) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedEntityCollectionFilterOPSupportsExplicitRegistration)(
        taIds, taIdsCount);
}

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPSupportsExplicitRegistration_server(server_rec* sv,
                                                                      char** taIds,
                                                                      size_t taIdsCount) {
    OIDFED_MAYLOAD_SERVER(return, oidfedEntityCollectionFilterOPSupportsExplicitRegistration)(
        taIds, taIdsCount);
}

static uintptr_t (*OIFFn_oidfedEntityCollectionFilterOPSupportsAutomaticRegistration)(
    char** taIds,
    size_t taIdsCount) = 0;

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPSupportsAutomaticRegistration(request_rec* r,
                                                                       char** taIds,
                                                                       size_t taIdsCount) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedEntityCollectionFilterOPSupportsAutomaticRegistration)(
        taIds, taIdsCount);
}

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPSupportsAutomaticRegistration_server(server_rec* sv,
                                                                       char** taIds,
                                                                       size_t taIdsCount) {
    OIDFED_MAYLOAD_SERVER(return, oidfedEntityCollectionFilterOPSupportsAutomaticRegistration)(
        taIds, taIdsCount);
}

static uintptr_t (*OIFFn_oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes)(
    char** taIds,
    size_t taIdsCount,
    char** grantTypes,
    size_t grantTypesCount) = 0;

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes(request_rec* r,
                                                                     char** taIds,
                                                                     size_t taIdsCount,
                                                                     char** grantTypes,
                                                                     size_t grantTypesCount) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes)(
        taIds, taIdsCount, grantTypes, grantTypesCount);
}

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes_server(server_rec* sv,
                                                                     char** taIds,
                                                                     size_t taIdsCount,
                                                                     char** grantTypes,
                                                                     size_t grantTypesCount) {
    OIDFED_MAYLOAD_SERVER(return, oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes)(
        taIds, taIdsCount, grantTypes, grantTypesCount);
}


static uintptr_t (*OIFFn_oidfedEntityCollectionFilterOPSupportedScopesIncludes)(
    char** taIds,
    size_t taIdsCount,
    char** scopes,
    size_t scopesCount) = 0;

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPSupportedScopesIncludes(request_rec* r,
                                                                 char** taIds,
                                                                 size_t taIdsCount,
                                                                 char** scopes,
                                                                 size_t scopesCount) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedEntityCollectionFilterOPSupportedScopesIncludes)(
        taIds, taIdsCount, scopes, scopesCount);
}

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPSupportedScopesIncludes_server(server_rec* sv,
                                                                 char** taIds,
                                                                 size_t taIdsCount,
                                                                 char** scopes,
                                                                 size_t scopesCount) {
    OIDFED_MAYLOAD_SERVER(return, oidfedEntityCollectionFilterOPSupportedScopesIncludes)(
        taIds, taIdsCount, scopes, scopesCount);
}

static uintptr_t (*OIFFn_oidfedEntityCollectionFilterOPs)(void) = 0;

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPs(request_rec* r) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedEntityCollectionFilterOPs)();
}

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPs_server(server_rec* sv) {
    OIDFED_MAYLOAD_SERVER(return, oidfedEntityCollectionFilterOPs)();
}

static int (*OIFFn_oidfedGoRtPing)(void) = 0;

int
OIFMayLoad_oidfedGoRtPing(request_rec* r) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedGoRtPing)();
}

int
OIFMayLoad_oidfedGoRtPing_server(server_rec* sv) {
    OIDFED_MAYLOAD_SERVER(return, oidfedGoRtPing)();
}

static void (*OIFFn_oidfedCollectorDestroy)(struct oidfed_collector* collector) = 0;

void
OIFMayLoad_oidfedCollectorDestroy(request_rec* r,
                                  struct oidfed_collector* collector) {
    OIDFED_MAYLOAD_REQUEST(, oidfedCollectorDestroy)(collector);
}

void
OIFMayLoad_oidfedCollectorDestroy_server(server_rec* sv,
                                  struct oidfed_collector* collector) {
    OIDFED_MAYLOAD_SERVER(, oidfedCollectorDestroy)(collector);
}

static struct oidfed_collector (*OIFFn_oidfedCollectorCreateSimple)(void) = 0;

struct oidfed_collector
OIFMayLoad_oidfedCollectorCreateSimple(request_rec* r) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedCollectorCreateSimple)();
}

struct oidfed_collector
OIFMayLoad_oidfedCollectorCreateSimple_server(server_rec* sv) {
    OIDFED_MAYLOAD_SERVER(return, oidfedCollectorCreateSimple)();
}

static struct oidfed_collector (*OIFFn_oidfedCollectorCreateSmart)(
    struct oidfed_trust_anchor* anchors,
    size_t anchorsCount) = 0;

struct oidfed_collector
OIFMayLoad_oidfedCollectorCreateSmart(request_rec* r,
                                      struct oidfed_trust_anchor* anchors,
                                      size_t anchorsCount) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedCollectorCreateSmart)(anchors, anchorsCount);
}

struct oidfed_collector
OIFMayLoad_oidfedCollectorCreateSmart_server(server_rec* sv,
                                      struct oidfed_trust_anchor* anchors,
                                      size_t anchorsCount) {
    OIDFED_MAYLOAD_SERVER(return, oidfedCollectorCreateSmart)(anchors, anchorsCount);
}

static int (*OIFFn_oidfedCollectorCollectVerifiedEntities)(
    struct oidfed_trust_anchor ta,
    struct oidfed_collector* collector,
    struct oidfed_collected_entity** entities,
    size_t* entitiesCount) = 0;

int
OIFMayLoad_oidfedCollectorCollectVerifiedEntities(request_rec* r,
                                                  struct oidfed_trust_anchor ta,
                                                  struct oidfed_collector* collector,
                                                  struct oidfed_collected_entity** entities,
                                                  size_t* entitiesCount) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedCollectorCollectVerifiedEntities)(
        ta, collector, entities, entitiesCount);
}

int
OIFMayLoad_oidfedCollectorCollectVerifiedEntities_server(server_rec* sv,
                                                  struct oidfed_trust_anchor ta,
                                                  struct oidfed_collector* collector,
                                                  struct oidfed_collected_entity** entities,
                                                  size_t* entitiesCount) {
    OIDFED_MAYLOAD_SERVER(return, oidfedCollectorCollectVerifiedEntities)(
        ta, collector, entities, entitiesCount);
}

static int (*OIFFn_oidfedCollectorCollectVerifiedEntitiesWithFilter)(struct oidfed_trust_anchor ta,
                                                                     struct oidfed_collector* collector,
                                                                     struct oidfed_collection_filter filters,
                                                                     struct oidfed_collected_entity** entities,
                                                                     size_t* entitiesCount) = 0;

int
OIFMayLoad_oidfedCollectorCollectVerifiedEntitiesWithFilter(request_rec* r,
                                                            struct oidfed_trust_anchor ta,
                                                            struct oidfed_collector* collector,
                                                            struct oidfed_collection_filter filters,
                                                            struct oidfed_collected_entity** entities,
                                                            size_t* entitiesCount) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedCollectorCollectVerifiedEntitiesWithFilter)(
        ta, collector, filters, entities, entitiesCount);
}

int
OIFMayLoad_oidfedCollectorCollectVerifiedEntitiesWithFilter_server(server_rec* sv,
                                                            struct oidfed_trust_anchor ta,
                                                            struct oidfed_collector* collector,
                                                            struct oidfed_collection_filter filters,
                                                            struct oidfed_collected_entity** entities,
                                                            size_t* entitiesCount) {
    OIDFED_MAYLOAD_SERVER(return, oidfedCollectorCollectVerifiedEntitiesWithFilter)(
        ta, collector, filters, entities, entitiesCount);
}

static struct oidfed_entity_statement (*OIFFn_oidfedEntityStatementParse)(
    char* jwt,
    size_t jwtLen,
    int* errc) = 0;

struct oidfed_entity_statement
OIFMayLoad_oidfedEntityStatementParse(request_rec* r,
                                      char* jwt, size_t jwtLen, int* errc) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedEntityStatementParse)(jwt, jwtLen, errc);
}

struct oidfed_entity_statement
OIFMayLoad_oidfedEntityStatementParse_server(server_rec* sv,
                                      char* jwt, size_t jwtLen, int* errc) {
    OIDFED_MAYLOAD_SERVER(return, oidfedEntityStatementParse)(jwt, jwtLen, errc);
}

static void (*OIFFn_oidfedEntityStatementDestroy)(struct oidfed_entity_statement* stmt) = 0;

void
OIFMayLoad_oidfedEntityStatementDestroy(request_rec* r, struct oidfed_entity_statement* stmt) {
    OIDFED_MAYLOAD_REQUEST(, oidfedEntityStatementDestroy)(stmt);
}

void
OIFMayLoad_oidfedEntityStatementDestroy_server(server_rec* sv, struct oidfed_entity_statement* stmt) {
    OIDFED_MAYLOAD_SERVER(, oidfedEntityStatementDestroy)(stmt);
}

static struct oidfed_entity_statement (*OIFFn_oidfedGetEntityConfiguration)(
    char* entityID, int* errc) = 0;

struct oidfed_entity_statement
OIFMayLoad_oidfedGetEntityConfiguration(request_rec* r, char* entityID, int* errc) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedGetEntityConfiguration)(entityID, errc);
}

struct oidfed_entity_statement
OIFMayLoad_oidfedGetEntityConfiguration_server(server_rec* sv, char* entityID, int* errc) {
    OIDFED_MAYLOAD_SERVER(return, oidfedGetEntityConfiguration)(entityID, errc);
}

static struct oidfed_federation_leaf (*OIFFn_oidfedFederationLeafCreateSimple)(
    char* entityID, struct oidfed_versatile_signer signer, int* errc) = 0;

struct oidfed_federation_leaf
OIFMayLoad_oidfedFederationLeafCreateSimple(request_rec* r,
                                            char* entityID,
                                            struct oidfed_versatile_signer signer,
                                            int* errc) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedFederationLeafCreateSimple)(entityID, signer, errc);
}

struct oidfed_federation_leaf
OIFMayLoad_oidfedFederationLeafCreateSimple_server(server_rec* sv,
                                            char* entityID,
                                            struct oidfed_versatile_signer signer,
                                            int* errc) {
    OIDFED_MAYLOAD_SERVER(return, oidfedFederationLeafCreateSimple)(entityID, signer, errc);
}

static void (*OIFFn_oidfedFederationLeafDestroy)(struct oidfed_federation_leaf* leaf) = 0;

void
OIFMayLoad_oidfedFederationLeafDestroy(request_rec* r,
                                       struct oidfed_federation_leaf* leaf) {
    OIDFED_MAYLOAD_REQUEST(, oidfedFederationLeafDestroy)(leaf);
}

void
OIFMayLoad_oidfedFederationLeafDestroy_server(server_rec* sv,
                                       struct oidfed_federation_leaf* leaf) {
    OIDFED_MAYLOAD_SERVER(, oidfedFederationLeafDestroy)(leaf);
}

static struct oidfed_request_producer (*OIFFn_oidfedFederationLeafGetRequestObjectProducer)(
    struct oidfed_federation_leaf leaf) = 0;

struct oidfed_request_producer
OIFMayLoad_oidfedFederationLeafGetRequestObjectProducer(request_rec* r,
                                                        struct oidfed_federation_leaf leaf) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedFederationLeafGetRequestObjectProducer)(leaf);
}

struct oidfed_request_producer
OIFMayLoad_oidfedFederationLeafGetRequestObjectProducer_server(server_rec* sv,
                                                        struct oidfed_federation_leaf leaf) {
    OIDFED_MAYLOAD_SERVER(return, oidfedFederationLeafGetRequestObjectProducer)(leaf);
}

static struct oidfed_map (*OIFFn_oidfCreateMap)(void) = 0;

struct oidfed_map
OIFMayLoad_oidfCreateMap(request_rec* r) {
    OIDFED_MAYLOAD_REQUEST(return, oidfCreateMap)();
}

struct oidfed_map
OIFMayLoad_oidfCreateMap_server(server_rec* sv) {
    OIDFED_MAYLOAD_SERVER(return, oidfCreateMap)();
}

static _Bool (*OIFFn_oidfMapHasKey)(struct oidfed_map m, char* key) = 0;

_Bool
OIFMayLoad_oidfMapHasKey(request_rec* r, struct oidfed_map m, char* key) {
    OIDFED_MAYLOAD_REQUEST(return, oidfMapHasKey)(m, key);
}

_Bool
OIFMayLoad_oidfMapHasKey_server(server_rec* sv, struct oidfed_map m, char* key) {
    OIDFED_MAYLOAD_SERVER(return, oidfMapHasKey)(m, key);
}

static void (*OIFFn_oidfMapSetString)(struct oidfed_map m, char* key, char* value) = 0;

void
OIFMayLoad_oidfMapSetString(request_rec* r, struct oidfed_map m, char* key, char* value) {
    OIDFED_MAYLOAD_REQUEST(, oidfMapSetString)(m, key, value);
}

void
OIFMayLoad_oidfMapSetString_server(server_rec* sv, struct oidfed_map m, char* key, char* value) {
    OIDFED_MAYLOAD_SERVER(, oidfMapSetString)(m, key, value);
}

static void (*OIFFn_oidfMapSetInt64)(struct oidfed_map m, char* key, int64_t value) = 0;

void
OIFMayLoad_oidfMapSetInt64(request_rec* r, struct oidfed_map m, char* key, int64_t value) {
    OIDFED_MAYLOAD_REQUEST(return, oidfMapSetInt64)(m, key, value);
}

void
OIFMayLoad_oidfMapSetInt64_server(server_rec* sv, struct oidfed_map m, char* key, int64_t value) {
    OIDFED_MAYLOAD_SERVER(return, oidfMapSetInt64)(m, key, value);
}

static struct oidfed_metadata (*OIFFn_oidfedMetadataCreate)(void) = 0;

struct oidfed_metadata
OIFMayLoad_oidfedMetadataCreate(request_rec* r) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedMetadataCreate)();
}

struct oidfed_metadata
OIFMayLoad_oidfedMetadataCreate_server(server_rec* sv) {
    OIDFED_MAYLOAD_SERVER(return, oidfedMetadataCreate)();
}

static uintptr_t (*OIFFn_oidfedMetadataGetOPMetadata)(struct oidfed_metadata m) = 0;

uintptr_t
OIFMayLoad_oidfedMetadataGetOPMetadata(request_rec* r, struct oidfed_metadata m) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedMetadataGetOPMetadata)(m);
}

uintptr_t
OIFMayLoad_oidfedMetadataGetOPMetadata_server(server_rec* sv, struct oidfed_metadata m) {
    OIDFED_MAYLOAD_SERVER(return, oidfedMetadataGetOPMetadata)(m);
}

static void (*OIFFn_oidfedMetadataSetOPMetadata)(struct oidfed_metadata m, uintptr_t op) = 0;

void
OIFMayLoad_oidfedMetadataSetOPMetadata(request_rec* r, struct oidfed_metadata m, uintptr_t op) {
    OIDFED_MAYLOAD_REQUEST(, oidfedMetadataSetOPMetadata)(m, op);
}

void
OIFMayLoad_oidfedMetadataSetOPMetadata_server(server_rec* sv, struct oidfed_metadata m, uintptr_t op) {
    OIDFED_MAYLOAD_SERVER(, oidfedMetadataSetOPMetadata)(m, op);
}

static uintptr_t (*OIFFn_oidfedMetadataGetRPMetadata)(struct oidfed_metadata m) = 0;

uintptr_t
OIFMayLoad_oidfedMetadataGetRPMetadata(request_rec* r, struct oidfed_metadata m) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedMetadataGetRPMetadata)(m);
}

uintptr_t
OIFMayLoad_oidfedMetadataGetRPMetadata_server(server_rec* sv, struct oidfed_metadata m) {
    OIDFED_MAYLOAD_SERVER(return, oidfedMetadataGetRPMetadata)(m);
}

static void (*OIFFn_oidfedMetadataSetRPMetadata)(struct oidfed_metadata m, uintptr_t rp) = 0;

void
OIFMayLoad_oidfedMetadataSetRPMetadata(request_rec* r, struct oidfed_metadata m, uintptr_t rp) {
    OIDFED_MAYLOAD_REQUEST(, oidfedMetadataSetRPMetadata)(m, rp);
}

void
OIFMayLoad_oidfedMetadataSetRPMetadata_server(server_rec* sv, struct oidfed_metadata m, uintptr_t rp) {
    OIDFED_MAYLOAD_SERVER(, oidfedMetadataSetRPMetadata)(m, rp);
}


static struct oidfed_request_producer (*OIFFn_oidfedRequestProducerCreate)(
    char* entityId, int64_t duration,
    struct oidfed_versatile_signer signer) = 0;

struct oidfed_request_producer
OIFMayLoad_oidfedRequestProducerCreate(request_rec* r,
                                       char* entityId,
                                       int64_t duration,
                                       struct oidfed_versatile_signer signer) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedRequestProducerCreate)(entityId, duration, signer);
}

struct oidfed_request_producer
OIFMayLoad_oidfedRequestProducerCreate_server(server_rec* sv,
                                       char* entityId,
                                       int64_t duration,
                                       struct oidfed_versatile_signer signer) {
    OIDFED_MAYLOAD_SERVER(return, oidfedRequestProducerCreate)(entityId, duration, signer);
}

static void (*OIFFn_oidfedRequestProducerDestroy)(struct oidfed_request_producer* producer) = 0;

void
OIFMayLoad_oidfedRequestProducerDestroy(request_rec* r,
                                        struct oidfed_request_producer* producer) {
    OIDFED_MAYLOAD_REQUEST(, oidfedRequestProducerDestroy)(producer);
}

void
OIFMayLoad_oidfedRequestProducerDestroy_server(server_rec* sv,
                                        struct oidfed_request_producer* producer) {
    OIDFED_MAYLOAD_SERVER(, oidfedRequestProducerDestroy)(producer);
}

static struct oidfed_signed_bytes (*OIFFn_oidfedRequestProducerProduceObject)(
    struct oidfed_request_producer producer,
    struct oidfed_map requestValues,
    char** algorithms,
    size_t algorithmsCount,
    int* errc) = 0;

struct oidfed_signed_bytes
OIFMayLoad_oidfedRequestProducerProduceObject(request_rec* r,
                                              struct oidfed_request_producer producer,
                                              struct oidfed_map requestValues,
                                              char** algorithms, size_t algorithmsCount,
                                              int* errc) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedRequestProducerProduceObject)(
        producer,
        requestValues,
        algorithms,
        algorithmsCount,
        errc);
}

struct oidfed_signed_bytes
OIFMayLoad_oidfedRequestProducerProduceObject_server(server_rec* sv,
                                              struct oidfed_request_producer producer,
                                              struct oidfed_map requestValues,
                                              char** algorithms, size_t algorithmsCount,
                                              int* errc) {
    OIDFED_MAYLOAD_SERVER(return, oidfedRequestProducerProduceObject)(
        producer,
        requestValues,
        algorithms,
        algorithmsCount,
        errc);
}

static struct oidfed_signed_bytes (*OIFFn_oidfedRequestProducerClientAssertion)(
    struct oidfed_request_producer producer, char* audience, char** algorithms, size_t algorithmsCount, int* errc) = 0;

struct oidfed_signed_bytes
OIFMayLoad_oidfedRequestProducerClientAssertion(request_rec* r,
                                                struct oidfed_request_producer producer,
                                                char* audience,
                                                char** algorithms,
                                                size_t algorithmsCount,
                                                int* errc) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedRequestProducerClientAssertion)(
        producer, audience, algorithms, algorithmsCount, errc);
}

struct oidfed_signed_bytes
OIFMayLoad_oidfedRequestProducerClientAssertion_server(server_rec* sv,
                                                struct oidfed_request_producer producer,
                                                char* audience,
                                                char** algorithms,
                                                size_t algorithmsCount,
                                                int* errc) {
    OIDFED_MAYLOAD_SERVER(return, oidfedRequestProducerClientAssertion)(
        producer, audience, algorithms, algorithmsCount, errc);
}

static void (*OIFFn_oidfedSignedBytesDestroy)(struct oidfed_signed_bytes* sb) = 0;

void
OIFMayLoad_oidfedSignedBytesDestroy(request_rec* r, struct oidfed_signed_bytes* sb) {
    OIDFED_MAYLOAD_REQUEST(, oidfedSignedBytesDestroy)(sb);
}

void
OIFMayLoad_oidfedSignedBytesDestroy_server(server_rec* sv, struct oidfed_signed_bytes* sb) {
    OIDFED_MAYLOAD_SERVER(, oidfedSignedBytesDestroy)(sb);
}

static char* (*OIFFn_oidfedSignedBytesGetData)(struct oidfed_signed_bytes sb, size_t* count) = 0;

char*
OIFMayLoad_oidfedSignedBytesGetData(request_rec* r,
                                    struct oidfed_signed_bytes sb,
                                    size_t* count) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedSignedBytesGetData)(sb, count);
}

char*
OIFMayLoad_oidfedSignedBytesGetData_server(server_rec* sv,
                                    struct oidfed_signed_bytes sb,
                                    size_t* count) {
    OIDFED_MAYLOAD_SERVER(return, oidfedSignedBytesGetData)(sb, count);
}

static struct oidfed_signature_algorithm (*OIFFn_oidfedSignatureAlgorithmCreateEmpty)(void) = 0;

struct oidfed_signature_algorithm
OIFMayLoad_oidfedSignatureAlgorithmCreateEmpty(request_rec* r) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedSignatureAlgorithmCreateEmpty)();
}

struct oidfed_signature_algorithm
OIFMayLoad_oidfedSignatureAlgorithmCreateEmpty_server(server_rec* sv) {
    OIDFED_MAYLOAD_SERVER(return, oidfedSignatureAlgorithmCreateEmpty)();
}

static void (*OIFFn_oidfedSignatureAlgorithmDestroy)(struct oidfed_signature_algorithm* sa) = 0;

void
OIFMayLoad_oidfedSignatureAlgorithmDestroy(request_rec* r,
                                           struct oidfed_signature_algorithm* sa) {
    OIDFED_MAYLOAD_REQUEST(, oidfedSignatureAlgorithmDestroy)(sa);
}

void
OIFMayLoad_oidfedSignatureAlgorithmDestroy_server(server_rec* sv,
                                           struct oidfed_signature_algorithm* sa) {
    OIDFED_MAYLOAD_SERVER(, oidfedSignatureAlgorithmDestroy)(sa);
}

static struct oidfed_signature_algorithm (*OIFFn_oidfedSignatureAlgorithmGet)(char* name, _Bool* succ) = 0;

struct oidfed_signature_algorithm
OIFMayLoad_oidfedSignatureAlgorithmGet(request_rec* r, char* name, _Bool* succ) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedSignatureAlgorithmGet)(name, succ);
}

struct oidfed_signature_algorithm
OIFMayLoad_oidfedSignatureAlgorithmGet_server(server_rec* sv, char* name, _Bool* succ) {
    OIDFED_MAYLOAD_SERVER(return, oidfedSignatureAlgorithmGet)(name, succ);
}

static struct oidfed_signer (*OIFFn_oidfedSignerCreateFromPEM)(char* pemBytes, size_t pemCount, int* errc) = 0;

struct oidfed_signer
OIFMayLoad_oidfedSignerCreateFromPEM(request_rec* r, char* pemBytes, size_t pemCount, int* errc) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedSignerCreateFromPEM)(pemBytes, pemCount, errc);
}

struct oidfed_signer
OIFMayLoad_oidfedSignerCreateFromPEM_server(server_rec* sv, char* pemBytes, size_t pemCount, int* errc) {
    OIDFED_MAYLOAD_SERVER(return, oidfedSignerCreateFromPEM)(pemBytes, pemCount, errc);
}

static void (*OIFFn_oidfedSignerDestroy)(struct oidfed_signer* s) = 0;

void
OIFMayLoad_oidfedSignerDestroy(request_rec* r, struct oidfed_signer* s) {
    OIDFED_MAYLOAD_REQUEST(, oidfedSignerDestroy)(s);
}

void
OIFMayLoad_oidfedSignerDestroy_server(server_rec* sv, struct oidfed_signer* s) {
    OIDFED_MAYLOAD_SERVER(, oidfedSignerDestroy)(s);
}

static struct oidfed_single_key_storage (*OIFFn_oidfedSingleKeyStorageCreate)(
    struct oidfed_signer signer, struct oidfed_signature_algorithm alg) = 0;

struct oidfed_single_key_storage
OIFMayLoad_oidfedSingleKeyStorageCreate(request_rec* r,
                                        struct oidfed_signer signer,
                                        struct oidfed_signature_algorithm alg) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedSingleKeyStorageCreate)(signer, alg);
}

struct oidfed_single_key_storage
OIFMayLoad_oidfedSingleKeyStorageCreate_server(server_rec* sv,
                                        struct oidfed_signer signer,
                                        struct oidfed_signature_algorithm alg) {
    OIDFED_MAYLOAD_SERVER(return, oidfedSingleKeyStorageCreate)(signer, alg);
}

static void (*OIFFn_oidfedSingleKeyStorageDestroy)(struct oidfed_single_key_storage* sks) = 0;

void
OIFMayLoad_oidfedSingleKeyStorageDestroy(request_rec* r,
                                         struct oidfed_single_key_storage* sks) {
    OIDFED_MAYLOAD_REQUEST(, oidfedSingleKeyStorageDestroy)(sks);
}

void
OIFMayLoad_oidfedSingleKeyStorageDestroy_server(server_rec* sv,
                                         struct oidfed_single_key_storage* sks) {
    OIDFED_MAYLOAD_SERVER(, oidfedSingleKeyStorageDestroy)(sks);
}

static void (*OIFFn_oidfedTrustAnchorDestroy)(struct oidfed_trust_anchor* ta) = 0;

void
OIFMayLoad_oidfedTrustAnchorDestroy(request_rec* r,
                                    struct oidfed_trust_anchor* ta) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustAnchorDestroy)(ta);
}

void
OIFMayLoad_oidfedTrustAnchorDestroy_server(server_rec* sv,
                                    struct oidfed_trust_anchor* ta) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustAnchorDestroy)(ta);
}

static struct oidfed_trust_anchor (*OIFFn_oidfedTrustAnchorCreate)(char* id) = 0;

struct oidfed_trust_anchor
OIFMayLoad_oidfedTrustAnchorCreate(request_rec* r, char* id) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustAnchorCreate)(id);
}

struct oidfed_trust_anchor
OIFMayLoad_oidfedTrustAnchorCreate_server(server_rec* sv, char* id) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustAnchorCreate)(id);
}

static struct oidfed_trust_mark (*OIFFn_oidfedTrustMarkCreate)(void) = 0;

struct oidfed_trust_mark
OIFMayLoad_oidfedTrustMarkCreate(request_rec* r) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustMarkCreate)();
}

struct oidfed_trust_mark
OIFMayLoad_oidfedTrustMarkCreate_server(server_rec* sv) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustMarkCreate)();
}

static void (*OIFFn_oidfedTrustMarkSetType)(struct oidfed_trust_mark tm, char* typ) = 0;

void
OIFMayLoad_oidfedTrustMarkSetType(request_rec* r, struct oidfed_trust_mark tm, char* typ) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustMarkSetType)(tm, typ);
}

void
OIFMayLoad_oidfedTrustMarkSetType_server(server_rec* sv, struct oidfed_trust_mark tm, char* typ) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustMarkSetType)(tm, typ);
}

static char* (*OIFFn_oidfedTrustMarkGetType)(struct oidfed_trust_mark tm) = 0;

char*
OIFMayLoad_oidfedTrustMarkGetType(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustMarkGetType)(tm);
}

char*
OIFMayLoad_oidfedTrustMarkGetType_server(server_rec* sv, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustMarkGetType)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetIssuer)(struct oidfed_trust_mark tm, char* issuer) = 0;

void
OIFMayLoad_oidfedTrustMarkSetIssuer(request_rec* r, struct oidfed_trust_mark tm, char* issuer) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustMarkSetIssuer)(tm, issuer);
}

void
OIFMayLoad_oidfedTrustMarkSetIssuer_server(server_rec* sv, struct oidfed_trust_mark tm, char* issuer) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustMarkSetIssuer)(tm, issuer);
}

static char* (*OIFFn_oidfedTrustMarkGetIssuer)(struct oidfed_trust_mark tm) = 0;

char*
OIFMayLoad_oidfedTrustMarkGetIssuer(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustMarkGetIssuer)(tm);
}

char*
OIFMayLoad_oidfedTrustMarkGetIssuer_server(server_rec* sv, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustMarkGetIssuer)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetSelfIssued)(
    struct oidfed_trust_mark tm, _Bool selfIssued) = 0;

void
OIFMayLoad_oidfedTrustMarkSetSelfIssued(request_rec* r,
                                        struct oidfed_trust_mark tm,
                                        _Bool selfIssued) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustMarkSetSelfIssued)(tm, selfIssued);
}

void
OIFMayLoad_oidfedTrustMarkSetSelfIssued_server(server_rec* sv,
                                        struct oidfed_trust_mark tm,
                                        _Bool selfIssued) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustMarkSetSelfIssued)(tm, selfIssued);
}

static _Bool (*OIFFn_oidfedTrustMarkIsSelfIssued)(struct oidfed_trust_mark tm) = 0;

_Bool
OIFMayLoad_oidfedTrustMarkIsSelfIssued(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustMarkIsSelfIssued)(tm);
}

_Bool
OIFMayLoad_oidfedTrustMarkIsSelfIssued_server(server_rec* sv, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustMarkIsSelfIssued)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetJwt)(struct oidfed_trust_mark tm, char* jwt) = 0;

void
OIFMayLoad_oidfedTrustMarkSetJwt(request_rec* r,
                                 struct oidfed_trust_mark tm,
                                 char* jwt) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustMarkSetJwt)(tm, jwt);
}

void
OIFMayLoad_oidfedTrustMarkSetJwt_server(server_rec* sv,
                                 struct oidfed_trust_mark tm,
                                 char* jwt) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustMarkSetJwt)(tm, jwt);
}

static char* (*OIFFn_oidfedTrustMarkGetJwt)(struct oidfed_trust_mark tm) = 0;

char*
OIFMayLoad_oidfedTrustMarkGetJwt(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustMarkGetJwt)(tm);
}

char*
OIFMayLoad_oidfedTrustMarkGetJwt_server(server_rec* sv, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustMarkGetJwt)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetRefresh)(struct oidfed_trust_mark tm, _Bool refresh) = 0;

void
OIFMayLoad_oidfedTrustMarkSetRefresh(request_rec* r,
                                     struct oidfed_trust_mark tm,
                                     _Bool refresh) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustMarkSetRefresh)(tm, refresh);
}

void
OIFMayLoad_oidfedTrustMarkSetRefresh_server(server_rec* sv,
                                     struct oidfed_trust_mark tm,
                                     _Bool refresh) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustMarkSetRefresh)(tm, refresh);
}

static _Bool (*OIFFn_oidfedTrustMarkIsRefresh)(struct oidfed_trust_mark tm) = 0;

_Bool
OIFMayLoad_oidfedTrustMarkIsRefresh(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustMarkIsRefresh)(tm);
}

_Bool
OIFMayLoad_oidfedTrustMarkIsRefresh_server(server_rec* sv, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustMarkIsRefresh)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetMinLifetimeSeconds)(struct oidfed_trust_mark tm,
                                                          uint64_t minLifetime) = 0;

void
OIFMayLoad_oidfedTrustMarkSetMinLifetimeSeconds(request_rec* r,
                                                struct oidfed_trust_mark tm,
                                                uint64_t minLifetime) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustMarkSetMinLifetimeSeconds)(tm, minLifetime);
}

void
OIFMayLoad_oidfedTrustMarkSetMinLifetimeSeconds_server(server_rec* sv,
                                                struct oidfed_trust_mark tm,
                                                uint64_t minLifetime) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustMarkSetMinLifetimeSeconds)(tm, minLifetime);
}

static uint64_t (*OIFFn_oidfedTrustMarkGetMinLifetimeSeconds)(struct oidfed_trust_mark tm) = 0;

uint64_t
OIFMayLoad_oidfedTrustMarkGetMinLifetimeSeconds(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustMarkGetMinLifetimeSeconds)(tm);
}

uint64_t
OIFMayLoad_oidfedTrustMarkGetMinLifetimeSeconds_server(server_rec* sv, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustMarkGetMinLifetimeSeconds)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetRefreshGracePeriod)(struct oidfed_trust_mark tm,
                                                          uint64_t refreshGracePeriod) = 0;

void
OIFMayLoad_oidfedTrustMarkSetRefreshGracePeriod(request_rec* r,
                                                struct oidfed_trust_mark tm,
                                                uint64_t refreshGracePeriod) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustMarkSetRefreshGracePeriod)(tm, refreshGracePeriod);
}

void
OIFMayLoad_oidfedTrustMarkSetRefreshGracePeriod_server(server_rec* sv,
                                                struct oidfed_trust_mark tm,
                                                uint64_t refreshGracePeriod) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustMarkSetRefreshGracePeriod)(tm, refreshGracePeriod);
}

static uint64_t (*OIFFn_oidfedTrustMarkGetRefreshGracePeriod)(struct oidfed_trust_mark tm) = 0;

uint64_t
OIFMayLoad_oidfedTrustMarkGetRefreshGracePeriod(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustMarkGetRefreshGracePeriod)(tm);
}

uint64_t
OIFMayLoad_oidfedTrustMarkGetRefreshGracePeriod_server(server_rec* sv, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustMarkGetRefreshGracePeriod)(tm);
}

static void (*OIFFn_oidfedTrustMarkDestroy)(struct oidfed_trust_mark* tm) = 0;

void
OIFMayLoad_oidfedTrustMarkDestroy(request_rec* r, struct oidfed_trust_mark* tm) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustMarkDestroy)(tm);
}

void
OIFMayLoad_oidfedTrustMarkDestroy_server(server_rec* sv, struct oidfed_trust_mark* tm) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustMarkDestroy)(tm);
}

static struct oidfed_trust_resolver (*OIFFn_oidfedTrustResolverCreate)(
    char* subID, struct oidfed_trust_anchor* anchors,
    size_t anchorsCount) = 0;

struct oidfed_trust_resolver
OIFMayLoad_oidfedTrustResolverCreate(request_rec* r,
                                     char* subID,
                                     struct oidfed_trust_anchor* anchors,
                                     size_t anchorsCount) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustResolverCreate)(subID, anchors, anchorsCount);
}

struct oidfed_trust_resolver
OIFMayLoad_oidfedTrustResolverCreate_server(server_rec* sv,
                                     char* subID,
                                     struct oidfed_trust_anchor* anchors,
                                     size_t anchorsCount) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustResolverCreate)(subID, anchors, anchorsCount);
}

static void (*OIFFn_oidfedTrustResolverDestroy)(struct oidfed_trust_resolver* r) = 0;

void
OIFMayLoad_oidfedTrustResolverDestroy(request_rec* r, struct oidfed_trust_resolver* rx) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustResolverDestroy)(rx);
}

void
OIFMayLoad_oidfedTrustResolverDestroy_server(server_rec* sv, struct oidfed_trust_resolver* rx) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustResolverDestroy)(rx);
}

static struct oidfed_trust_chains (*OIFFn_oidfedTrustResolverResolveToValidChains)(
    struct oidfed_trust_resolver r) = 0;

struct oidfed_trust_chains
OIFMayLoad_oidfedTrustResolverResolveToValidChains(request_rec* r,
                                                   struct oidfed_trust_resolver rx) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustResolverResolveToValidChains)(rx);
}

struct oidfed_trust_chains
OIFMayLoad_oidfedTrustResolverResolveToValidChains_server(server_rec* sv,
                                                   struct oidfed_trust_resolver rx) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustResolverResolveToValidChains)(rx);
}

static size_t (*OIFFn_oidfedTrustChainsCount)(struct oidfed_trust_chains chains) = 0;

size_t
OIFMayLoad_oidfedTrustChainsCount(request_rec* r, struct oidfed_trust_chains chains) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustChainsCount)(chains);
}

size_t
OIFMayLoad_oidfedTrustChainsCount_server(server_rec* sv, struct oidfed_trust_chains chains) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustChainsCount)(chains);
}

static struct oidfed_trust_chain (*OIFFn_oidfedTrustChainsGet)(
    struct oidfed_trust_chains chains, size_t index) = 0;

struct oidfed_trust_chain
OIFMayLoad_oidfedTrustChainsGet(request_rec* r,
                                struct oidfed_trust_chains chains,
                                size_t index) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustChainsGet)(chains, index);
}

struct oidfed_trust_chain
OIFMayLoad_oidfedTrustChainsGet_server(server_rec* sv,
                                struct oidfed_trust_chains chains,
                                size_t index) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustChainsGet)(chains, index);
}

static void (*OIFFn_oidfedTrustChainsDestroy)(struct oidfed_trust_chains* chains) = 0;

void
OIFMayLoad_oidfedTrustChainsDestroy(request_rec* r,
                                    struct oidfed_trust_chains* chains) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustChainsDestroy)(chains);
}

void
OIFMayLoad_oidfedTrustChainsDestroy_server(server_rec* sv,
                                    struct oidfed_trust_chains* chains) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustChainsDestroy)(chains);
}

static void (*OIFFn_oidfedTrustChainDestroy)(struct oidfed_trust_chain* chain) = 0;

void
OIFMayLoad_oidfedTrustChainDestroy(request_rec* r, struct oidfed_trust_chain* chain) {
    OIDFED_MAYLOAD_REQUEST(, oidfedTrustChainDestroy)(chain);
}

void
OIFMayLoad_oidfedTrustChainDestroy_server(server_rec* sv, struct oidfed_trust_chain* chain) {
    OIDFED_MAYLOAD_SERVER(, oidfedTrustChainDestroy)(chain);
}

static struct oidfed_metadata (*OIFFn_oidfedTrustChainGetMetadata)(
    struct oidfed_trust_chain chain, int* errc) = 0;

struct oidfed_metadata
OIFMayLoad_oidfedTrustChainGetMetadata(request_rec* r,
                                       struct oidfed_trust_chain chain,
                                       int* errc) {
    OIDFED_MAYLOAD_REQUEST(return, oidfedTrustChainGetMetadata)(chain, errc);
}

struct oidfed_metadata
OIFMayLoad_oidfedTrustChainGetMetadata_server(server_rec* sv,
                                       struct oidfed_trust_chain chain,
                                       int* errc) {
    OIDFED_MAYLOAD_SERVER(return, oidfedTrustChainGetMetadata)(chain, errc);
}

static void (*OIFFn_oidfedMetadataDestroy)(struct oidfed_metadata* m) = 0;

void
OIFMayLoad_oidfedMetadataDestroy(request_rec* r, struct oidfed_metadata* m) {
    OIDFED_MAYLOAD_REQUEST(, oidfedMetadataDestroy)(m);
}

void
OIFMayLoad_oidfedMetadataDestroy_server(server_rec* sv, struct oidfed_metadata* m) {
    OIDFED_MAYLOAD_SERVER(, oidfedMetadataDestroy)(m);
}

static void (*OIFFn_oidfedUiInfoDestroy)(struct oidfed_ui_info* ui) = 0;

void
OIFMayLoad_oidfedUiInfoDestroy(request_rec* r, struct oidfed_ui_info* ui) {
    OIDFED_MAYLOAD_REQUEST(, oidfedUiInfoDestroy)(ui);
}

void
OIFMayLoad_oidfedUiInfoDestroy_server(server_rec* sv, struct oidfed_ui_info* ui) {
    OIDFED_MAYLOAD_SERVER(, oidfedUiInfoDestroy)(ui);
}
