#include <ap_config.h>
#include <httpd.h>
#include <http_log.h>

#include <assert.h>
#include <dlfcn.h>

#include <oidfed_wrap_loader.h>

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

#define OIDFED_MAYLOAD(ret, fn) do { \
    if (LIKELY(OIDFED_CAT(OIDFED_FN_HOLDER_PREFIX, fn))) break; \
    void* dynlib = NULL; \
    apr_pool_userdata_get(&dynlib, OIDFED_WORKER_DYNLIB_HANDLE, r->server->process->pconf); \
    if (UNLIKELY(dynlib == NULL)) { \
        ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "oidfedWrap called without initialization!"); \
        assert(false && "module invariant broken: oidfed_worker_init() not called"); \
    } \
    void* sym = dlsym(dynlib, APR_STRINGIFY(fn)); \
    if (UNLIKELY(!sym)) { \
        ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, \
            "oidfedWrap: symbol '%s' is not found in wrap library.", \
            APR_STRINGIFY(fn)); \
        assert(false && "module invariant broken: incompatible wrap library found"); \
    } \
    OIDFED_CAT(OIDFED_FN_HOLDER_PREFIX, fn) = sym;\
} while (0); \
ret OIDFED_CAT(OIDFED_FN_HOLDER_PREFIX, fn)

static apr_status_t
oidfed_worker_deinit_dynlib(void* data) {
    dlclose(data);
    return APR_SUCCESS;
}

apr_status_t
oidfed_worker_init(const struct oidfed_worker_config* cfg, apr_pool_t* p) {
    printf("EEEEEE: %s\n", OIDFED_WORKER_DYNLIB_PATH);
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
    printf("EEEE222EE: %s %p\n", OIDFED_WORKER_DYNLIB_PATH, dl);
    return apr_pool_userdata_set(dl, OIDFED_WORKER_DYNLIB_HANDLE, oidfed_worker_deinit_dynlib, p);
}

static void (*OIFFn_oidfedCollectedEntityDestroy)(struct oidfed_collected_entity* ce) = 0;

void
OIFMayLoad_oidfedCollectedEntityDestroy(request_rec* r, struct oidfed_collected_entity* ce) {
    OIDFED_MAYLOAD(, oidfedCollectedEntityDestroy)(ce);
}

static struct oidfed_collected_entity_ui_enumerator (*OIFFn_oidfedCollectedEntityEnumerateUi)(
    struct oidfed_collected_entity ce) = 0;

struct oidfed_collected_entity_ui_enumerator
OIFMayLoad_oidfedCollectedEntityEnumerateUi(request_rec* r,
                                            struct oidfed_collected_entity ce) {
    OIDFED_MAYLOAD(return, oidfedCollectedEntityEnumerateUi)(ce);
}

static _Bool (*OIFFn_oidfedCollectedEntityNextUi)(struct oidfed_collected_entity_ui_enumerator* enumer) = 0;

_Bool
OIFMayLoad_oidfedCollectedEntityNextUi(request_rec* r,
                                       struct oidfed_collected_entity_ui_enumerator* enumer) {
    OIDFED_MAYLOAD(return, oidfedCollectedEntityNextUi)(enumer);
}

static void (*OIFFn_oidfedCollectedEntityFinishUi)(struct oidfed_collected_entity_ui_enumerator* enumer) = 0;

void
OIFMayLoad_oidfedCollectedEntityFinishUi(request_rec* r,
                                         struct oidfed_collected_entity_ui_enumerator* enumer) {
    OIDFED_MAYLOAD(, oidfedCollectedEntityFinishUi)(enumer);
}

static struct oidfed_ui_info (*OIFFn_oidfedCollectedEntityGetUiValue)(
    struct oidfed_collected_entity_ui_enumerator* enumer) = 0;

struct oidfed_ui_info
OIFMayLoad_oidfedCollectedEntityGetUiValue(request_rec* r,
                                           struct oidfed_collected_entity_ui_enumerator* enumer) {
    OIDFED_MAYLOAD(return, oidfedCollectedEntityGetUiValue)(enumer);
}

static struct oidfed_collection_filter (*OIFFn_oidfedEmptyCollectionFilter)(void) = 0;

struct oidfed_collection_filter
OIFMayLoad_oidfedEmptyCollectionFilter(request_rec* r) {
    OIDFED_MAYLOAD(return, oidfedEmptyCollectionFilter)();
}

static void (*OIFFn_oidfedCollectionFilterDestroy)(struct oidfed_collection_filter* cfs) = 0;

void
OIFMayLoad_oidfedCollectionFilterDestroy(request_rec* r,
                                         struct oidfed_collection_filter* cfs) {
    OIDFED_MAYLOAD(, oidfedCollectionFilterDestroy)(cfs);
}

static void (*OIFFn_oidfedCollectionFilterAppend)(struct oidfed_collection_filter* cfs,
                                                  uintptr_t filter) = 0;

void
OIFMayLoad_oidfedCollectionFilterAppend(request_rec* r,
                                        struct oidfed_collection_filter* cfs,
                                        uintptr_t filter) {
    OIDFED_MAYLOAD(, oidfedCollectionFilterAppend)(cfs, filter);
}

static uintptr_t (*OIFFn_oidfedEntityCollectionFilterOPSupportsExplicitRegistration)(
    char** taIds,
    size_t taIdsCount) = 0;

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPSupportsExplicitRegistration(request_rec* r,
                                                                      char** taIds,
                                                                      size_t taIdsCount) {
    OIDFED_MAYLOAD(return, oidfedEntityCollectionFilterOPSupportsExplicitRegistration)(
        taIds, taIdsCount);
}

static uintptr_t (*OIFFn_oidfedEntityCollectionFilterOPSupportsAutomaticRegistration)(
    char** taIds,
    size_t taIdsCount) = 0;

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPSupportsAutomaticRegistration(request_rec* r,
                                                                       char** taIds,
                                                                       size_t taIdsCount) {
    OIDFED_MAYLOAD(return, oidfedEntityCollectionFilterOPSupportsAutomaticRegistration)(
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
    OIDFED_MAYLOAD(return, oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes)(
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
    OIDFED_MAYLOAD(return, oidfedEntityCollectionFilterOPSupportedScopesIncludes)(
        taIds, taIdsCount, scopes, scopesCount);
}

static uintptr_t (*OIFFn_oidfedEntityCollectionFilterOPs)(void) = 0;

uintptr_t
OIFMayLoad_oidfedEntityCollectionFilterOPs(request_rec* r) {
    OIDFED_MAYLOAD(return, oidfedEntityCollectionFilterOPs)();
}

static int (*OIFFn_oidfedGoRtPing)(void) = 0;

int
OIFMayLoad_oidfedGoRtPing(request_rec* r) {
    OIDFED_MAYLOAD(return, oidfedGoRtPing)();
}

static void (*OIFFn_oidfedCollectorDestroy)(struct oidfed_collector* collector) = 0;

void
OIFMayLoad_oidfedCollectorDestroy(request_rec* r,
                                  struct oidfed_collector* collector) {
    OIDFED_MAYLOAD(, oidfedCollectorDestroy)(collector);
}

static struct oidfed_collector (*OIFFn_oidfedCollectorCreateSimple)(void) = 0;

struct oidfed_collector
OIFMayLoad_oidfedCollectorCreateSimple(request_rec* r) {
    OIDFED_MAYLOAD(return, oidfedCollectorCreateSimple)();
}

static struct oidfed_collector (*OIFFn_oidfedCollectorCreateSmart)(
    struct oidfed_trust_anchor* anchors,
    size_t anchorsCount) = 0;

struct oidfed_collector
OIFMayLoad_oidfedCollectorCreateSmart(request_rec* r,
                                      struct oidfed_trust_anchor* anchors,
                                      size_t anchorsCount) {
    OIDFED_MAYLOAD(return, oidfedCollectorCreateSmart)(anchors, anchorsCount);
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
    OIDFED_MAYLOAD(return, oidfedCollectorCollectVerifiedEntities)(
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
    OIDFED_MAYLOAD(return, oidfedCollectorCollectVerifiedEntitiesWithFilter)(
        ta, collector, filters, entities, entitiesCount);
}

static struct oidfed_entity_statement (*OIFFn_oidfedEntityStatementParse)(
    char* jwt,
    size_t jwtLen,
    int* errc) = 0;

struct oidfed_entity_statement
OIFMayLoad_oidfedEntityStatementParse(request_rec* r,
                                      char* jwt, size_t jwtLen, int* errc) {
    OIDFED_MAYLOAD(return, oidfedEntityStatementParse)(jwt, jwtLen, errc);
}

static void (*OIFFn_oidfedEntityStatementDestroy)(struct oidfed_entity_statement* stmt) = 0;

void
OIFMayLoad_oidfedEntityStatementDestroy(request_rec* r, struct oidfed_entity_statement* stmt) {
    OIDFED_MAYLOAD(, oidfedEntityStatementDestroy)(stmt);
}

static struct oidfed_entity_statement (*OIFFn_oidfedGetEntityConfiguration)(
    char* entityID, int* errc) = 0;

struct oidfed_entity_statement
OIFMayLoad_oidfedGetEntityConfiguration(request_rec* r, char* entityID, int* errc) {
    OIDFED_MAYLOAD(return, oidfedGetEntityConfiguration)(entityID, errc);
}

static struct oidfed_federation_leaf (*OIFFn_oidfedFederationLeafCreateSimple)(
    char* entityID, struct oidfed_versatile_signer signer, int* errc) = 0;

struct oidfed_federation_leaf
OIFMayLoad_oidfedFederationLeafCreateSimple(request_rec* r,
                                            char* entityID,
                                            struct oidfed_versatile_signer signer,
                                            int* errc) {
    OIDFED_MAYLOAD(return, oidfedFederationLeafCreateSimple)(entityID, signer, errc);
}

static void (*OIFFn_oidfedFederationLeafDestroy)(struct oidfed_federation_leaf* leaf) = 0;

void
OIFMayLoad_oidfedFederationLeafDestroy(request_rec* r,
                                       struct oidfed_federation_leaf* leaf) {
    OIDFED_MAYLOAD(, oidfedFederationLeafDestroy)(leaf);
}

static struct oidfed_request_producer (*OIFFn_oidfedFederationLeafGetRequestObjectProducer)(
    struct oidfed_federation_leaf leaf) = 0;

struct oidfed_request_producer
OIFMayLoad_oidfedFederationLeafGetRequestObjectProducer(request_rec* r,
                                                        struct oidfed_federation_leaf leaf) {
    OIDFED_MAYLOAD(return, oidfedFederationLeafGetRequestObjectProducer)(leaf);
}

static struct oidfed_map (*OIFFn_oidfCreateMap)(void) = 0;

struct oidfed_map
OIFMayLoad_oidfCreateMap(request_rec* r) {
    OIDFED_MAYLOAD(return, oidfCreateMap)();
}

static _Bool (*OIFFn_oidfMapHasKey)(struct oidfed_map m, char* key) = 0;

_Bool
OIFMayLoad_oidfMapHasKey(request_rec* r, struct oidfed_map m, char* key) {
    OIDFED_MAYLOAD(return, oidfMapHasKey)(m, key);
}

static void (*OIFFn_oidfMapSetString)(struct oidfed_map m, char* key, char* value) = 0;

void
OIFMayLoad_oidfMapSetString(request_rec* r, struct oidfed_map m, char* key, char* value) {
    OIDFED_MAYLOAD(, oidfMapSetString)(m, key, value);
}

static void (*OIFFn_oidfMapSetInt64)(struct oidfed_map m, char* key, int64_t value) = 0;

void
OIFMayLoad_oidfMapSetInt64(request_rec* r, struct oidfed_map m, char* key, int64_t value) {
    OIDFED_MAYLOAD(return, oidfMapSetInt64)(m, key, value);
}

static struct oidfed_metadata (*OIFFn_oidfedMetadataCreate)(void) = 0;

struct oidfed_metadata
OIFMayLoad_oidfedMetadataCreate(request_rec* r) {
    OIDFED_MAYLOAD(return, oidfedMetadataCreate)();
}

static uintptr_t (*OIFFn_oidfedMetadataGetOPMetadata)(struct oidfed_metadata m) = 0;

uintptr_t
OIFMayLoad_oidfedMetadataGetOPMetadata(request_rec* r, struct oidfed_metadata m) {
    OIDFED_MAYLOAD(return, oidfedMetadataGetOPMetadata)(m);
}

static void (*OIFFn_oidfedMetadataSetOPMetadata)(struct oidfed_metadata m, uintptr_t op) = 0;

void
OIFMayLoad_oidfedMetadataSetOPMetadata(request_rec* r, struct oidfed_metadata m, uintptr_t op) {
    OIDFED_MAYLOAD(, oidfedMetadataSetOPMetadata)(m, op);
}

static uintptr_t (*OIFFn_oidfedMetadataGetRPMetadata)(struct oidfed_metadata m) = 0;

uintptr_t
OIFMayLoad_oidfedMetadataGetRPMetadata(request_rec* r, struct oidfed_metadata m) {
    OIDFED_MAYLOAD(return, oidfedMetadataGetRPMetadata)(m);
}

static void (*OIFFn_oidfedMetadataSetRPMetadata)(struct oidfed_metadata m, uintptr_t rp) = 0;

void
OIFMayLoad_oidfedMetadataSetRPMetadata(request_rec* r, struct oidfed_metadata m, uintptr_t rp) {
    OIDFED_MAYLOAD(, oidfedMetadataSetRPMetadata)(m, rp);
}


static struct oidfed_request_producer (*OIFFn_oidfedRequestProducerCreate)(
    char* entityId, int64_t duration,
    struct oidfed_versatile_signer signer) = 0;

struct oidfed_request_producer
OIFMayLoad_oidfedRequestProducerCreate(request_rec* r,
                                       char* entityId,
                                       int64_t duration,
                                       struct oidfed_versatile_signer signer) {
    OIDFED_MAYLOAD(return, oidfedRequestProducerCreate)(entityId, duration, signer);
}

static void (*OIFFn_oidfedRequestProducerDestroy)(struct oidfed_request_producer* producer) = 0;

void
OIFMayLoad_oidfedRequestProducerDestroy(request_rec* r,
                                        struct oidfed_request_producer* producer) {
    OIDFED_MAYLOAD(, oidfedRequestProducerDestroy)(producer);
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
    OIDFED_MAYLOAD(return, oidfedRequestProducerProduceObject)(
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
    OIDFED_MAYLOAD(return, oidfedRequestProducerClientAssertion)(
        producer, audience, algorithms, algorithmsCount, errc);
}

static void (*OIFFn_oidfedSignedBytesDestroy)(struct oidfed_signed_bytes* sb) = 0;

void
OIFMayLoad_oidfedSignedBytesDestroy(request_rec* r, struct oidfed_signed_bytes* sb) {
    OIDFED_MAYLOAD(, oidfedSignedBytesDestroy)(sb);
}

static char* (*OIFFn_oidfedSignedBytesGetData)(struct oidfed_signed_bytes sb, size_t* count) = 0;

char*
OIFMayLoad_oidfedSignedBytesGetData(request_rec* r,
                                    struct oidfed_signed_bytes sb,
                                    size_t* count) {
    OIDFED_MAYLOAD(return, oidfedSignedBytesGetData)(sb, count);
}

static struct oidfed_signature_algorithm (*OIFFn_oidfedSignatureAlgorithmCreateEmpty)(void) = 0;

struct oidfed_signature_algorithm
OIFMayLoad_oidfedSignatureAlgorithmCreateEmpty(request_rec* r) {
    OIDFED_MAYLOAD(return, oidfedSignatureAlgorithmCreateEmpty)();
}

static void (*OIFFn_oidfedSignatureAlgorithmDestroy)(struct oidfed_signature_algorithm* sa) = 0;

void
OIFMayLoad_oidfedSignatureAlgorithmDestroy(request_rec* r,
                                           struct oidfed_signature_algorithm* sa) {
    OIDFED_MAYLOAD(, oidfedSignatureAlgorithmDestroy)(sa);
}

static struct oidfed_signature_algorithm (*OIFFn_oidfedSignatureAlgorithmGet)(char* name, _Bool* succ) = 0;

struct oidfed_signature_algorithm
OIFMayLoad_oidfedSignatureAlgorithmGet(request_rec* r, char* name, _Bool* succ) {
    OIDFED_MAYLOAD(return, oidfedSignatureAlgorithmGet)(name, succ);
}

static struct oidfed_signer (*OIFFn_oidfedSignerCreateFromPEM)(char* pemBytes, size_t pemCount, int* errc) = 0;

struct oidfed_signer
OIFMayLoad_oidfedSignerCreateFromPEM(request_rec* r, char* pemBytes, size_t pemCount, int* errc) {
    OIDFED_MAYLOAD(return, oidfedSignerCreateFromPEM)(pemBytes, pemCount, errc);
}

static void (*OIFFn_oidfedSignerDestroy)(struct oidfed_signer* s) = 0;

void
OIFMayLoad_oidfedSignerDestroy(request_rec* r, struct oidfed_signer* s) {
    OIDFED_MAYLOAD(, oidfedSignerDestroy)(s);
}

static struct oidfed_single_key_storage (*OIFFn_oidfedSingleKeyStorageCreate)(
    struct oidfed_signer signer, struct oidfed_signature_algorithm alg) = 0;

struct oidfed_single_key_storage
OIFMayLoad_oidfedSingleKeyStorageCreate(request_rec* r,
                                        struct oidfed_signer signer,
                                        struct oidfed_signature_algorithm alg) {
    OIDFED_MAYLOAD(return, oidfedSingleKeyStorageCreate)(signer, alg);
}

static void (*OIFFn_oidfedSingleKeyStorageDestroy)(struct oidfed_single_key_storage* sks) = 0;

void
OIFMayLoad_oidfedSingleKeyStorageDestroy(request_rec* r,
                                         struct oidfed_single_key_storage* sks) {
    OIDFED_MAYLOAD(, oidfedSingleKeyStorageDestroy)(sks);
}

static void (*OIFFn_oidfedTrustAnchorDestroy)(struct oidfed_trust_anchor* ta) = 0;

void
OIFMayLoad_oidfedTrustAnchorDestroy(request_rec* r,
                                    struct oidfed_trust_anchor* ta) {
    OIDFED_MAYLOAD(, oidfedTrustAnchorDestroy)(ta);
}

static struct oidfed_trust_anchor (*OIFFn_oidfedTrustAnchorCreate)(char* id) = 0;

struct oidfed_trust_anchor
OIFMayLoad_oidfedTrustAnchorCreate(request_rec* r, char* id) {
    OIDFED_MAYLOAD(return, oidfedTrustAnchorCreate)(id);
}

static struct oidfed_trust_mark (*OIFFn_oidfedTrustMarkCreate)(void) = 0;

struct oidfed_trust_mark
OIFMayLoad_oidfedTrustMarkCreate(request_rec* r) {
    OIDFED_MAYLOAD(return, oidfedTrustMarkCreate)();
}

static void (*OIFFn_oidfedTrustMarkSetType)(struct oidfed_trust_mark tm, char* typ) = 0;

void
OIFMayLoad_oidfedTrustMarkSetType(request_rec* r, struct oidfed_trust_mark tm, char* typ) {
    OIDFED_MAYLOAD(, oidfedTrustMarkSetType)(tm, typ);
}

static char* (*OIFFn_oidfedTrustMarkGetType)(struct oidfed_trust_mark tm) = 0;

char*
OIFMayLoad_oidfedTrustMarkGetType(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD(return, oidfedTrustMarkGetType)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetIssuer)(struct oidfed_trust_mark tm, char* issuer) = 0;

void
OIFMayLoad_oidfedTrustMarkSetIssuer(request_rec* r, struct oidfed_trust_mark tm, char* issuer) {
    OIDFED_MAYLOAD(, oidfedTrustMarkSetIssuer)(tm, issuer);
}

static char* (*OIFFn_oidfedTrustMarkGetIssuer)(struct oidfed_trust_mark tm) = 0;

char*
OIFMayLoad_oidfedTrustMarkGetIssuer(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD(return, oidfedTrustMarkGetIssuer)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetSelfIssued)(
    struct oidfed_trust_mark tm, _Bool selfIssued) = 0;

void
OIFMayLoad_oidfedTrustMarkSetSelfIssued(request_rec* r,
                                        struct oidfed_trust_mark tm,
                                        _Bool selfIssued) {
    OIDFED_MAYLOAD(, oidfedTrustMarkSetSelfIssued)(tm, selfIssued);
}

static _Bool (*OIFFn_oidfedTrustMarkIsSelfIssued)(struct oidfed_trust_mark tm) = 0;

_Bool
OIFMayLoad_oidfedTrustMarkIsSelfIssued(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD(return, oidfedTrustMarkIsSelfIssued)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetJwt)(struct oidfed_trust_mark tm, char* jwt) = 0;

void
OIFMayLoad_oidfedTrustMarkSetJwt(request_rec* r,
                                 struct oidfed_trust_mark tm,
                                 char* jwt) {
    OIDFED_MAYLOAD(, oidfedTrustMarkSetJwt)(tm, jwt);
}

static char* (*OIFFn_oidfedTrustMarkGetJwt)(struct oidfed_trust_mark tm) = 0;

char*
OIFMayLoad_oidfedTrustMarkGetJwt(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD(return, oidfedTrustMarkGetJwt)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetRefresh)(struct oidfed_trust_mark tm, _Bool refresh) = 0;

void
OIFMayLoad_oidfedTrustMarkSetRefresh(request_rec* r,
                                     struct oidfed_trust_mark tm,
                                     _Bool refresh) {
    OIDFED_MAYLOAD(, oidfedTrustMarkSetRefresh)(tm, refresh);
}

static _Bool (*OIFFn_oidfedTrustMarkIsRefresh)(struct oidfed_trust_mark tm) = 0;

_Bool
OIFMayLoad_oidfedTrustMarkIsRefresh(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD(return, oidfedTrustMarkIsRefresh)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetMinLifetimeSeconds)(struct oidfed_trust_mark tm,
                                                          uint64_t minLifetime) = 0;

void
OIFMayLoad_oidfedTrustMarkSetMinLifetimeSeconds(request_rec* r,
                                                struct oidfed_trust_mark tm,
                                                uint64_t minLifetime) {
    OIDFED_MAYLOAD(, oidfedTrustMarkSetMinLifetimeSeconds)(tm, minLifetime);
}

static uint64_t (*OIFFn_oidfedTrustMarkGetMinLifetimeSeconds)(struct oidfed_trust_mark tm) = 0;

uint64_t
OIFMayLoad_oidfedTrustMarkGetMinLifetimeSeconds(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD(return, oidfedTrustMarkGetMinLifetimeSeconds)(tm);
}

static void (*OIFFn_oidfedTrustMarkSetRefreshGracePeriod)(struct oidfed_trust_mark tm,
                                                          uint64_t refreshGracePeriod) = 0;

void
OIFMayLoad_oidfedTrustMarkSetRefreshGracePeriod(request_rec* r,
                                                struct oidfed_trust_mark tm,
                                                uint64_t refreshGracePeriod) {
    OIDFED_MAYLOAD(, oidfedTrustMarkSetRefreshGracePeriod)(tm, refreshGracePeriod);
}

static uint64_t (*OIFFn_oidfedTrustMarkGetRefreshGracePeriod)(struct oidfed_trust_mark tm) = 0;

uint64_t
OIFMayLoad_oidfedTrustMarkGetRefreshGracePeriod(request_rec* r, struct oidfed_trust_mark tm) {
    OIDFED_MAYLOAD(return, oidfedTrustMarkGetRefreshGracePeriod)(tm);
}

static void (*OIFFn_oidfedTrustMarkDestroy)(struct oidfed_trust_mark* tm) = 0;

void
OIFMayLoad_oidfedTrustMarkDestroy(request_rec* r, struct oidfed_trust_mark* tm) {
    OIDFED_MAYLOAD(, oidfedTrustMarkDestroy)(tm);
}

static struct oidfed_trust_resolver (*OIFFn_oidfedTrustResolverCreate)(
    char* subID, struct oidfed_trust_anchor* anchors,
    size_t anchorsCount) = 0;

struct oidfed_trust_resolver
OIFMayLoad_oidfedTrustResolverCreate(request_rec* r,
                                     char* subID,
                                     struct oidfed_trust_anchor* anchors,
                                     size_t anchorsCount) {
    OIDFED_MAYLOAD(return, oidfedTrustResolverCreate)(subID, anchors, anchorsCount);
}

static void (*OIFFn_oidfedTrustResolverDestroy)(struct oidfed_trust_resolver* r) = 0;

void
OIFMayLoad_oidfedTrustResolverDestroy(request_rec* r, struct oidfed_trust_resolver* rx) {
    OIDFED_MAYLOAD(, oidfedTrustResolverDestroy)(rx);
}

static struct oidfed_trust_chains (*OIFFn_oidfedTrustResolverResolveToValidChains)(
    struct oidfed_trust_resolver r) = 0;

struct oidfed_trust_chains
OIFMayLoad_oidfedTrustResolverResolveToValidChains(request_rec* r,
                                                   struct oidfed_trust_resolver rx) {
    OIDFED_MAYLOAD(return, oidfedTrustResolverResolveToValidChains)(rx);
}

static size_t (*OIFFn_oidfedTrustChainsCount)(struct oidfed_trust_chains chains) = 0;

size_t
OIFMayLoad_oidfedTrustChainsCount(request_rec* r, struct oidfed_trust_chains chains) {
    OIDFED_MAYLOAD(return, oidfedTrustChainsCount)(chains);
}

static struct oidfed_trust_chain (*OIFFn_oidfedTrustChainsGet)(
    struct oidfed_trust_chains chains, size_t index) = 0;

struct oidfed_trust_chain
OIFMayLoad_oidfedTrustChainsGet(request_rec* r,
                                struct oidfed_trust_chains chains,
                                size_t index) {
    OIDFED_MAYLOAD(return, oidfedTrustChainsGet)(chains, index);
}

static void (*OIFFn_oidfedTrustChainsDestroy)(struct oidfed_trust_chains* chains) = 0;

void
OIFMayLoad_oidfedTrustChainsDestroy(request_rec* r,
                                    struct oidfed_trust_chains* chains) {
    OIDFED_MAYLOAD(, oidfedTrustChainsDestroy)(chains);
}

static void (*OIFFn_oidfedTrustChainDestroy)(struct oidfed_trust_chain* chain) = 0;

void
OIFMayLoad_oidfedTrustChainDestroy(request_rec* r, struct oidfed_trust_chain* chain) {
    OIDFED_MAYLOAD(, oidfedTrustChainDestroy)(chain);
}

static struct oidfed_metadata (*OIFFn_oidfedTrustChainGetMetadata)(
    struct oidfed_trust_chain chain, int* errc) = 0;

struct oidfed_metadata
OIFMayLoad_oidfedTrustChainGetMetadata(request_rec* r,
                                       struct oidfed_trust_chain chain,
                                       int* errc) {
    OIDFED_MAYLOAD(return, oidfedTrustChainGetMetadata)(chain, errc);
}

static void (*OIFFn_oidfedMetadataDestroy)(struct oidfed_metadata* m) = 0;

void
OIFMayLoad_oidfedMetadataDestroy(request_rec* r, struct oidfed_metadata* m) {
    OIDFED_MAYLOAD(, oidfedMetadataDestroy)(m);
}

static void (*OIFFn_oidfedUiInfoDestroy)(struct oidfed_ui_info* ui) = 0;

void
OIFMayLoad_oidfedUiInfoDestroy(request_rec* r, struct oidfed_ui_info* ui) {
    OIDFED_MAYLOAD(, oidfedUiInfoDestroy)(ui);
}
