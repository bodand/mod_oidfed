#ifndef OIDFED_OIDFED_WRAP_LOADER_H
#define OIDFED_OIDFED_WRAP_LOADER_H

#include <httpd/httpd.h>

#include <oidfed_config_fwd.h>
#include <oidfed_wrap_lib.h>

apr_status_t
oidfed_worker_init(const struct oidfed_worker_config* cfg, apr_pool_t* p);

#define oidfCreateMap(...) OIFMayLoad_oidfCreateMap(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectedEntityDestroy(...) OIFMayLoad_oidfedCollectedEntityDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectedEntityDestroy(...) OIFMayLoad_oidfedCollectedEntityDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectedEntityEnumerateUi(...) OIFMayLoad_oidfedCollectedEntityEnumerateUi(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectedEntityEnumerateUi(...) OIFMayLoad_oidfedCollectedEntityEnumerateUi(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectedEntityFinishUi(...) OIFMayLoad_oidfedCollectedEntityFinishUi(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectedEntityFinishUi(...) OIFMayLoad_oidfedCollectedEntityFinishUi(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectedEntityGetUiValue(...) OIFMayLoad_oidfedCollectedEntityGetUiValue(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectedEntityGetUiValue(...) OIFMayLoad_oidfedCollectedEntityGetUiValue(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectedEntityNextUi(...) OIFMayLoad_oidfedCollectedEntityNextUi(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectedEntityNextUi(...) OIFMayLoad_oidfedCollectedEntityNextUi(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectionFilterAppend(...) OIFMayLoad_oidfedCollectionFilterAppend(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectionFilterAppend(...) OIFMayLoad_oidfedCollectionFilterAppend(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectionFilterDestroy(...) OIFMayLoad_oidfedCollectionFilterDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectionFilterDestroy(...) OIFMayLoad_oidfedCollectionFilterDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectorCollectVerifiedEntities(...) OIFMayLoad_oidfedCollectorCollectVerifiedEntities(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectorCollectVerifiedEntitiesWithFilter(...) OIFMayLoad_oidfedCollectorCollectVerifiedEntitiesWithFilter(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectorCreateSimple(...) OIFMayLoad_oidfedCollectorCreateSimple(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectorCreateSmart(...) OIFMayLoad_oidfedCollectorCreateSmart(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedCollectorDestroy(...) OIFMayLoad_oidfedCollectorDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEmptyCollectionFilter(...) OIFMayLoad_oidfedEmptyCollectionFilter(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEmptyCollectionFilter(...) OIFMayLoad_oidfedEmptyCollectionFilter(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEntityCollectionFilterOPs(...) OIFMayLoad_oidfedEntityCollectionFilterOPs(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes(...) OIFMayLoad_oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes(...) OIFMayLoad_oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEntityCollectionFilterOPSupportedScopesIncludes(...) OIFMayLoad_oidfedEntityCollectionFilterOPSupportedScopesIncludes(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEntityCollectionFilterOPSupportsAutomaticRegistration(...) OIFMayLoad_oidfedEntityCollectionFilterOPSupportsAutomaticRegistration(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEntityCollectionFilterOPSupportsAutomaticRegistration(...) OIFMayLoad_oidfedEntityCollectionFilterOPSupportsAutomaticRegistration(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEntityCollectionFilterOPSupportsExplicitRegistration(...) OIFMayLoad_oidfedEntityCollectionFilterOPSupportsExplicitRegistration(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEntityCollectionFilterOPSupportsExplicitRegistration(...) OIFMayLoad_oidfedEntityCollectionFilterOPSupportsExplicitRegistration(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEntityStatementDestroy(...) OIFMayLoad_oidfedEntityStatementDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedEntityStatementParse(...) OIFMayLoad_oidfedEntityStatementParse(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedFederationLeafCreateSimple(...) OIFMayLoad_oidfedFederationLeafCreateSimple(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedFederationLeafDestroy(...) OIFMayLoad_oidfedFederationLeafDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedFederationLeafGetRequestObjectProducer(...) OIFMayLoad_oidfedFederationLeafGetRequestObjectProducer(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedGetEntityConfiguration(...) OIFMayLoad_oidfedGetEntityConfiguration(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedGoRtPing(...) OIFMayLoad_oidfedGoRtPing(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedMetadataCreate(...) OIFMayLoad_oidfedMetadataCreate(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedMetadataDestroy(...) OIFMayLoad_oidfedMetadataDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedMetadataDestroy(...) OIFMayLoad_oidfedMetadataDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedMetadataGetOPMetadata(...) OIFMayLoad_oidfedMetadataGetOPMetadata(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedMetadataGetRPMetadata(...) OIFMayLoad_oidfedMetadataGetRPMetadata(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedMetadataSetOPMetadata(...) OIFMayLoad_oidfedMetadataSetOPMetadata(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedMetadataSetRPMetadata(...) OIFMayLoad_oidfedMetadataSetRPMetadata(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedRequestProducerClientAssertion(...) OIFMayLoad_oidfedRequestProducerClientAssertion(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedRequestProducerCreate(...) OIFMayLoad_oidfedRequestProducerCreate(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedRequestProducerDestroy(...) OIFMayLoad_oidfedRequestProducerDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedRequestProducerProduceObject(...) OIFMayLoad_oidfedRequestProducerProduceObject(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedSignatureAlgorithmCreateEmpty(...) OIFMayLoad_oidfedSignatureAlgorithmCreateEmpty(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedSignatureAlgorithmDestroy(...) OIFMayLoad_oidfedSignatureAlgorithmDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedSignatureAlgorithmGet(...) OIFMayLoad_oidfedSignatureAlgorithmGet(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedSignedBytesDestroy(...) OIFMayLoad_oidfedSignedBytesDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedSignedBytesGetData(...) OIFMayLoad_oidfedSignedBytesGetData(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedSignerCreateFromPEM(...) OIFMayLoad_oidfedSignerCreateFromPEM(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedSignerDestroy(...) OIFMayLoad_oidfedSignerDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedSingleKeyStorageCreate(...) OIFMayLoad_oidfedSingleKeyStorageCreate(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedSingleKeyStorageDestroy(...) OIFMayLoad_oidfedSingleKeyStorageDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustAnchorCreate(...) OIFMayLoad_oidfedTrustAnchorCreate(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustAnchorDestroy(...) OIFMayLoad_oidfedTrustAnchorDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustChainDestroy(...) OIFMayLoad_oidfedTrustChainDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustChainDestroy(...) OIFMayLoad_oidfedTrustChainDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustChainGetMetadata(...) OIFMayLoad_oidfedTrustChainGetMetadata(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustChainGetMetadata(...) OIFMayLoad_oidfedTrustChainGetMetadata(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustChainsCount(...) OIFMayLoad_oidfedTrustChainsCount(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustChainsCount(...) OIFMayLoad_oidfedTrustChainsCount(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustChainsDestroy(...) OIFMayLoad_oidfedTrustChainsDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustChainsDestroy(...) OIFMayLoad_oidfedTrustChainsDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustChainsGet(...) OIFMayLoad_oidfedTrustChainsGet(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustChainsGet(...) OIFMayLoad_oidfedTrustChainsGet(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkCreate(...) OIFMayLoad_oidfedTrustMarkCreate(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkDestroy(...) OIFMayLoad_oidfedTrustMarkDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkDestroy(...) OIFMayLoad_oidfedTrustMarkDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkGetIssuer(...) OIFMayLoad_oidfedTrustMarkGetIssuer(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkGetJwt(...) OIFMayLoad_oidfedTrustMarkGetJwt(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkGetMinLifetimeSeconds(...) OIFMayLoad_oidfedTrustMarkGetMinLifetimeSeconds(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkGetRefreshGracePeriod(...) OIFMayLoad_oidfedTrustMarkGetRefreshGracePeriod(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkGetType(...) OIFMayLoad_oidfedTrustMarkGetType(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkIsRefresh(...) OIFMayLoad_oidfedTrustMarkIsRefresh(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkIsSelfIssued(...) OIFMayLoad_oidfedTrustMarkIsSelfIssued(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkSetIssuer(...) OIFMayLoad_oidfedTrustMarkSetIssuer(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkSetJwt(...) OIFMayLoad_oidfedTrustMarkSetJwt(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkSetMinLifetimeSeconds(...) OIFMayLoad_oidfedTrustMarkSetMinLifetimeSeconds(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkSetRefreshGracePeriod(...) OIFMayLoad_oidfedTrustMarkSetRefreshGracePeriod(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkSetRefresh(...) OIFMayLoad_oidfedTrustMarkSetRefresh(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkSetSelfIssued(...) OIFMayLoad_oidfedTrustMarkSetSelfIssued(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustMarkSetType(...) OIFMayLoad_oidfedTrustMarkSetType(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustResolverCreate(...) OIFMayLoad_oidfedTrustResolverCreate(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustResolverCreate(...) OIFMayLoad_oidfedTrustResolverCreate(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustResolverDestroy(...) OIFMayLoad_oidfedTrustResolverDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustResolverDestroy(...) OIFMayLoad_oidfedTrustResolverDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustResolverResolveToValidChains(...) OIFMayLoad_oidfedTrustResolverResolveToValidChains(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedTrustResolverResolveToValidChains(...) OIFMayLoad_oidfedTrustResolverResolveToValidChains(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedUiInfoDestroy(...) OIFMayLoad_oidfedUiInfoDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfedUiInfoDestroy(...) OIFMayLoad_oidfedUiInfoDestroy(r __VA_OPT__(,) __VA_ARGS__)
#define oidfMapHasKey(...) OIFMayLoad_oidfMapHasKey(r __VA_OPT__(,) __VA_ARGS__)
#define oidfMapSetInt64(...) OIFMayLoad_oidfMapSetInt64(r __VA_OPT__(,) __VA_ARGS__)
#define oidfMapSetString(...) OIFMayLoad_oidfMapSetString(r __VA_OPT__(,) __VA_ARGS__)

void OIFMayLoad_oidfedCollectedEntityDestroy(request_rec* r, struct oidfed_collected_entity* ce);

void OIFMayLoad_oidfedCollectedEntityDestroy_server(server_rec* sv, struct oidfed_collected_entity* ce);

struct oidfed_collected_entity_ui_enumerator OIFMayLoad_oidfedCollectedEntityEnumerateUi(request_rec* r,
    struct oidfed_collected_entity ce);

struct oidfed_collected_entity_ui_enumerator OIFMayLoad_oidfedCollectedEntityEnumerateUi_server(server_rec* sv,
    struct oidfed_collected_entity ce);

_Bool OIFMayLoad_oidfedCollectedEntityNextUi(request_rec* r, struct oidfed_collected_entity_ui_enumerator* enumer);

_Bool OIFMayLoad_oidfedCollectedEntityNextUi_server(server_rec* sv,
                                                    struct oidfed_collected_entity_ui_enumerator* enumer);

void OIFMayLoad_oidfedCollectedEntityFinishUi(request_rec* r, struct oidfed_collected_entity_ui_enumerator* enumer);

void OIFMayLoad_oidfedCollectedEntityFinishUi_server(server_rec* sv,
                                                     struct oidfed_collected_entity_ui_enumerator* enumer);

struct oidfed_ui_info OIFMayLoad_oidfedCollectedEntityGetUiValue(request_rec* r,
                                                                 struct oidfed_collected_entity_ui_enumerator* enumer);

struct oidfed_ui_info OIFMayLoad_oidfedCollectedEntityGetUiValue_server(server_rec* sv,
                                                                        struct oidfed_collected_entity_ui_enumerator*
                                                                        enumer);

struct oidfed_collection_filter OIFMayLoad_oidfedEmptyCollectionFilter(request_rec* r);

struct oidfed_collection_filter OIFMayLoad_oidfedEmptyCollectionFilter_server(server_rec* sv);

void OIFMayLoad_oidfedCollectionFilterDestroy(request_rec* r, struct oidfed_collection_filter* cfs);

void OIFMayLoad_oidfedCollectionFilterDestroy_server(server_rec* sv, struct oidfed_collection_filter* cfs);

void OIFMayLoad_oidfedCollectionFilterAppend(request_rec* r, struct oidfed_collection_filter* cfs, uintptr_t filter);

void OIFMayLoad_oidfedCollectionFilterAppend_server(server_rec* sv, struct oidfed_collection_filter* cfs,
                                                    uintptr_t filter);

uintptr_t OIFMayLoad_oidfedEntityCollectionFilterOPSupportsExplicitRegistration(
    request_rec* r, char** taIds, size_t taIdsCount);

uintptr_t OIFMayLoad_oidfedEntityCollectionFilterOPSupportsExplicitRegistration_server(
    server_rec* sv, char** taIds, size_t taIdsCount);

uintptr_t OIFMayLoad_oidfedEntityCollectionFilterOPSupportsAutomaticRegistration(
    request_rec* r, char** taIds, size_t taIdsCount);

uintptr_t OIFMayLoad_oidfedEntityCollectionFilterOPSupportsAutomaticRegistration_server(
    server_rec* sv, char** taIds, size_t taIdsCount);

uintptr_t OIFMayLoad_oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes(request_rec* r,
                                                                               char** taIds, size_t taIdsCount,
                                                                               char** grantTypes,
                                                                               size_t grantTypesCount);

uintptr_t OIFMayLoad_oidfedEntityCollectionFilterOPSupportedGrantTypesIncludes_server(server_rec* sv,
    char** taIds, size_t taIdsCount,
    char** grantTypes,
    size_t grantTypesCount);


uintptr_t OIFMayLoad_oidfedEntityCollectionFilterOPSupportedScopesIncludes(request_rec* r,
                                                                           char** taIds, size_t taIdsCount,
                                                                           char** scopes, size_t scopesCount);

uintptr_t OIFMayLoad_oidfedEntityCollectionFilterOPSupportedScopesIncludes_server(server_rec* sv,
    char** taIds, size_t taIdsCount,
    char** scopes, size_t scopesCount);

uintptr_t OIFMayLoad_oidfedEntityCollectionFilterOPs(request_rec* r);

uintptr_t OIFMayLoad_oidfedEntityCollectionFilterOPs_server(server_rec* sv);

int OIFMayLoad_oidfedGoRtPing(request_rec* r);

int OIFMayLoad_oidfedGoRtPing_server(server_rec* sv);

void OIFMayLoad_oidfedCollectorDestroy(request_rec* r, struct oidfed_collector* collector);

void OIFMayLoad_oidfedCollectorDestroy_server(server_rec* sv, struct oidfed_collector* collector);

struct oidfed_collector OIFMayLoad_oidfedCollectorCreateSimple(request_rec* r);

struct oidfed_collector OIFMayLoad_oidfedCollectorCreateSimple_server(server_rec* sv);

struct oidfed_collector OIFMayLoad_oidfedCollectorCreateSmart(request_rec* r, struct oidfed_trust_anchor* anchors,
                                                              size_t anchorsCount);

struct oidfed_collector OIFMayLoad_oidfedCollectorCreateSmart_server(server_rec* sv,
                                                                     struct oidfed_trust_anchor* anchors,
                                                                     size_t anchorsCount);

int OIFMayLoad_oidfedCollectorCollectVerifiedEntities(request_rec* r, struct oidfed_trust_anchor ta,
                                                      struct oidfed_collector* collector,
                                                      struct oidfed_collected_entity** entities, size_t* entitiesCount);

int OIFMayLoad_oidfedCollectorCollectVerifiedEntities_server(server_rec* sv, struct oidfed_trust_anchor ta,
                                                             struct oidfed_collector* collector,
                                                             struct oidfed_collected_entity** entities,
                                                             size_t* entitiesCount);

int OIFMayLoad_oidfedCollectorCollectVerifiedEntitiesWithFilter(request_rec* r, struct oidfed_trust_anchor ta,
                                                                struct oidfed_collector* collector,
                                                                struct oidfed_collection_filter filters,
                                                                struct oidfed_collected_entity** entities,
                                                                size_t* entitiesCount);

int OIFMayLoad_oidfedCollectorCollectVerifiedEntitiesWithFilter_server(server_rec* sv, struct oidfed_trust_anchor ta,
                                                                       struct oidfed_collector* collector,
                                                                       struct oidfed_collection_filter filters,
                                                                       struct oidfed_collected_entity** entities,
                                                                       size_t* entitiesCount);

struct oidfed_entity_statement OIFMayLoad_oidfedEntityStatementParse(request_rec* r, char* jwt, size_t jwtLen,
                                                                     int* errc);

struct oidfed_entity_statement OIFMayLoad_oidfedEntityStatementParse_server(server_rec* sv, char* jwt, size_t jwtLen,
                                                                            int* errc);

void OIFMayLoad_oidfedEntityStatementDestroy(request_rec* r, struct oidfed_entity_statement* stmt);

void OIFMayLoad_oidfedEntityStatementDestroy_server(server_rec* sv, struct oidfed_entity_statement* stmt);

struct oidfed_entity_statement OIFMayLoad_oidfedGetEntityConfiguration(request_rec* r, char* entityID, int* errc);

struct oidfed_entity_statement
OIFMayLoad_oidfedGetEntityConfiguration_server(server_rec* sv, char* entityID, int* errc);

struct oidfed_federation_leaf OIFMayLoad_oidfedFederationLeafCreateSimple(request_rec* r,
                                                                          char* entityID,
                                                                          struct oidfed_versatile_signer signer,
                                                                          int* errc);

struct oidfed_federation_leaf OIFMayLoad_oidfedFederationLeafCreateSimple_server(server_rec* sv,
    char* entityID,
    struct oidfed_versatile_signer signer,
    int* errc);

void OIFMayLoad_oidfedFederationLeafDestroy(request_rec* r, struct oidfed_federation_leaf* leaf);

void OIFMayLoad_oidfedFederationLeafDestroy_server(server_rec* sv, struct oidfed_federation_leaf* leaf);

struct oidfed_request_producer OIFMayLoad_oidfedFederationLeafGetRequestObjectProducer(request_rec* r,
    struct oidfed_federation_leaf leaf);

struct oidfed_request_producer OIFMayLoad_oidfedFederationLeafGetRequestObjectProducer_server(server_rec* sv,
    struct oidfed_federation_leaf leaf);

struct oidfed_map OIFMayLoad_oidfCreateMap(request_rec* r);

struct oidfed_map OIFMayLoad_oidfCreateMap_server(server_rec* sv);

_Bool OIFMayLoad_oidfMapHasKey(request_rec* r, struct oidfed_map m, char* key);

_Bool OIFMayLoad_oidfMapHasKey_server(server_rec* sv, struct oidfed_map m, char* key);

void OIFMayLoad_oidfMapSetString(request_rec* r, struct oidfed_map m, char* key, char* value);

void OIFMayLoad_oidfMapSetString_server(server_rec* sv, struct oidfed_map m, char* key, char* value);

void OIFMayLoad_oidfMapSetInt64(request_rec* r, struct oidfed_map m, char* key, int64_t value);

void OIFMayLoad_oidfMapSetInt64_server(server_rec* sv, struct oidfed_map m, char* key, int64_t value);

struct oidfed_metadata OIFMayLoad_oidfedMetadataCreate(request_rec* r);

struct oidfed_metadata OIFMayLoad_oidfedMetadataCreate_server(server_rec* sv);

uintptr_t OIFMayLoad_oidfedMetadataGetOPMetadata(request_rec* r, struct oidfed_metadata m);

uintptr_t OIFMayLoad_oidfedMetadataGetOPMetadata_server(server_rec* sv, struct oidfed_metadata m);

void OIFMayLoad_oidfedMetadataSetOPMetadata(request_rec* r, struct oidfed_metadata m, uintptr_t op);

void OIFMayLoad_oidfedMetadataSetOPMetadata_server(server_rec* sv, struct oidfed_metadata m, uintptr_t op);

uintptr_t OIFMayLoad_oidfedMetadataGetRPMetadata(request_rec* r, struct oidfed_metadata m);

uintptr_t OIFMayLoad_oidfedMetadataGetRPMetadata_server(server_rec* sv, struct oidfed_metadata m);

void OIFMayLoad_oidfedMetadataSetRPMetadata(request_rec* r, struct oidfed_metadata m, uintptr_t rp);

void OIFMayLoad_oidfedMetadataSetRPMetadata_server(server_rec* sv, struct oidfed_metadata m, uintptr_t rp);


struct oidfed_request_producer OIFMayLoad_oidfedRequestProducerCreate(request_rec* r, char* entityId, int64_t duration,

                                                                      struct oidfed_versatile_signer signer);

struct oidfed_request_producer OIFMayLoad_oidfedRequestProducerCreate_server(
    server_rec* sv, char* entityId, int64_t duration,

    struct oidfed_versatile_signer signer);

void OIFMayLoad_oidfedRequestProducerDestroy(request_rec* r, struct oidfed_request_producer* producer);

void OIFMayLoad_oidfedRequestProducerDestroy_server(server_rec* sv, struct oidfed_request_producer* producer);

struct oidfed_signed_bytes OIFMayLoad_oidfedRequestProducerProduceObject(request_rec* r,
                                                                         struct oidfed_request_producer producer,
                                                                         struct oidfed_map requestValues,
                                                                         char** algorithms, size_t algorithmsCount,
                                                                         int* errc);

struct oidfed_signed_bytes OIFMayLoad_oidfedRequestProducerProduceObject_server(server_rec* sv,
    struct oidfed_request_producer producer,
    struct oidfed_map requestValues,
    char** algorithms, size_t algorithmsCount,
    int* errc);

struct oidfed_signed_bytes OIFMayLoad_oidfedRequestProducerClientAssertion(request_rec* r,
                                                                           struct oidfed_request_producer producer,
                                                                           char* audience, char** algorithms,
                                                                           size_t algorithmsCount, int* errc);

struct oidfed_signed_bytes OIFMayLoad_oidfedRequestProducerClientAssertion_server(server_rec* sv,
    struct oidfed_request_producer producer,
    char* audience, char** algorithms,
    size_t algorithmsCount, int* errc);

void OIFMayLoad_oidfedSignedBytesDestroy(request_rec* r, struct oidfed_signed_bytes* sb);

void OIFMayLoad_oidfedSignedBytesDestroy_server(server_rec* sv, struct oidfed_signed_bytes* sb);

char* OIFMayLoad_oidfedSignedBytesGetData(request_rec* r, struct oidfed_signed_bytes sb, size_t* count);

char* OIFMayLoad_oidfedSignedBytesGetData_server(server_rec* sv, struct oidfed_signed_bytes sb, size_t* count);

struct oidfed_signature_algorithm OIFMayLoad_oidfedSignatureAlgorithmCreateEmpty(request_rec* r);

struct oidfed_signature_algorithm OIFMayLoad_oidfedSignatureAlgorithmCreateEmpty_server(server_rec* sv);

void OIFMayLoad_oidfedSignatureAlgorithmDestroy(request_rec* r, struct oidfed_signature_algorithm* sa);

void OIFMayLoad_oidfedSignatureAlgorithmDestroy_server(server_rec* sv, struct oidfed_signature_algorithm* sa);

struct oidfed_signature_algorithm OIFMayLoad_oidfedSignatureAlgorithmGet(request_rec* r, char* name, _Bool* succ);

struct oidfed_signature_algorithm
OIFMayLoad_oidfedSignatureAlgorithmGet_server(server_rec* sv, char* name, _Bool* succ);

struct oidfed_signer OIFMayLoad_oidfedSignerCreateFromPEM(request_rec* r, char* pemBytes, size_t pemCount, int* errc);

struct oidfed_signer OIFMayLoad_oidfedSignerCreateFromPEM_server(server_rec* sv, char* pemBytes, size_t pemCount,
                                                                 int* errc);

void OIFMayLoad_oidfedSignerDestroy(request_rec* r, struct oidfed_signer* s);

void OIFMayLoad_oidfedSignerDestroy_server(server_rec* sv, struct oidfed_signer* s);

struct oidfed_single_key_storage OIFMayLoad_oidfedSingleKeyStorageCreate(request_rec* r,
                                                                         struct oidfed_signer signer,
                                                                         struct oidfed_signature_algorithm alg);

struct oidfed_single_key_storage OIFMayLoad_oidfedSingleKeyStorageCreate_server(server_rec* sv,
    struct oidfed_signer signer,
    struct oidfed_signature_algorithm alg);

void OIFMayLoad_oidfedSingleKeyStorageDestroy(request_rec* r, struct oidfed_single_key_storage* sks);

void OIFMayLoad_oidfedSingleKeyStorageDestroy_server(server_rec* sv, struct oidfed_single_key_storage* sks);

void OIFMayLoad_oidfedTrustAnchorDestroy(request_rec* r, struct oidfed_trust_anchor* ta);

void OIFMayLoad_oidfedTrustAnchorDestroy_server(server_rec* sv, struct oidfed_trust_anchor* ta);

struct oidfed_trust_anchor OIFMayLoad_oidfedTrustAnchorCreate(request_rec* r, char* id);

struct oidfed_trust_anchor OIFMayLoad_oidfedTrustAnchorCreate_server(server_rec* sv, char* id);

struct oidfed_trust_mark OIFMayLoad_oidfedTrustMarkCreate(request_rec* r);

struct oidfed_trust_mark OIFMayLoad_oidfedTrustMarkCreate_server(server_rec* sv);

void OIFMayLoad_oidfedTrustMarkSetType(request_rec* r, struct oidfed_trust_mark tm, char* typ);

void OIFMayLoad_oidfedTrustMarkSetType_server(server_rec* sv, struct oidfed_trust_mark tm, char* typ);

char* OIFMayLoad_oidfedTrustMarkGetType(request_rec* r, struct oidfed_trust_mark tm);

char* OIFMayLoad_oidfedTrustMarkGetType_server(server_rec* sv, struct oidfed_trust_mark tm);

void OIFMayLoad_oidfedTrustMarkSetIssuer(request_rec* r, struct oidfed_trust_mark tm, char* issuer);

void OIFMayLoad_oidfedTrustMarkSetIssuer_server(server_rec* sv, struct oidfed_trust_mark tm, char* issuer);

char* OIFMayLoad_oidfedTrustMarkGetIssuer(request_rec* r, struct oidfed_trust_mark tm);

char* OIFMayLoad_oidfedTrustMarkGetIssuer_server(server_rec* sv, struct oidfed_trust_mark tm);

void OIFMayLoad_oidfedTrustMarkSetSelfIssued(request_rec* r, struct oidfed_trust_mark tm, _Bool selfIssued);

void OIFMayLoad_oidfedTrustMarkSetSelfIssued_server(server_rec* sv, struct oidfed_trust_mark tm, _Bool selfIssued);

_Bool OIFMayLoad_oidfedTrustMarkIsSelfIssued(request_rec* r, struct oidfed_trust_mark tm);

_Bool OIFMayLoad_oidfedTrustMarkIsSelfIssued_server(server_rec* sv, struct oidfed_trust_mark tm);

void OIFMayLoad_oidfedTrustMarkSetJwt(request_rec* r, struct oidfed_trust_mark tm, char* jwt);

void OIFMayLoad_oidfedTrustMarkSetJwt_server(server_rec* sv, struct oidfed_trust_mark tm, char* jwt);

char* OIFMayLoad_oidfedTrustMarkGetJwt(request_rec* r, struct oidfed_trust_mark tm);

char* OIFMayLoad_oidfedTrustMarkGetJwt_server(server_rec* sv, struct oidfed_trust_mark tm);

void OIFMayLoad_oidfedTrustMarkSetRefresh(request_rec* r, struct oidfed_trust_mark tm, _Bool refresh);

void OIFMayLoad_oidfedTrustMarkSetRefresh_server(server_rec* sv, struct oidfed_trust_mark tm, _Bool refresh);

_Bool OIFMayLoad_oidfedTrustMarkIsRefresh(request_rec* r, struct oidfed_trust_mark tm);

_Bool OIFMayLoad_oidfedTrustMarkIsRefresh_server(server_rec* sv, struct oidfed_trust_mark tm);

void OIFMayLoad_oidfedTrustMarkSetMinLifetimeSeconds(request_rec* r, struct oidfed_trust_mark tm, uint64_t minLifetime);

void OIFMayLoad_oidfedTrustMarkSetMinLifetimeSeconds_server(server_rec* sv, struct oidfed_trust_mark tm,
                                                            uint64_t minLifetime);

uint64_t OIFMayLoad_oidfedTrustMarkGetMinLifetimeSeconds(request_rec* r, struct oidfed_trust_mark tm);

uint64_t OIFMayLoad_oidfedTrustMarkGetMinLifetimeSeconds_server(server_rec* sv, struct oidfed_trust_mark tm);

void OIFMayLoad_oidfedTrustMarkSetRefreshGracePeriod(request_rec* r, struct oidfed_trust_mark tm,
                                                     uint64_t refreshGracePeriod);

void OIFMayLoad_oidfedTrustMarkSetRefreshGracePeriod_server(server_rec* sv, struct oidfed_trust_mark tm,
                                                            uint64_t refreshGracePeriod);

uint64_t OIFMayLoad_oidfedTrustMarkGetRefreshGracePeriod(request_rec* r, struct oidfed_trust_mark tm);

uint64_t OIFMayLoad_oidfedTrustMarkGetRefreshGracePeriod_server(server_rec* sv, struct oidfed_trust_mark tm);

void OIFMayLoad_oidfedTrustMarkDestroy(request_rec* r, struct oidfed_trust_mark* tm);

void OIFMayLoad_oidfedTrustMarkDestroy_server(server_rec* sv, struct oidfed_trust_mark* tm);

struct oidfed_trust_resolver OIFMayLoad_oidfedTrustResolverCreate(request_rec* r, char* subID,
                                                                  struct oidfed_trust_anchor* anchors,
                                                                  size_t anchorsCount);

struct oidfed_trust_resolver OIFMayLoad_oidfedTrustResolverCreate_server(server_rec* sv, char* subID,
                                                                         struct oidfed_trust_anchor* anchors,
                                                                         size_t anchorsCount);

void OIFMayLoad_oidfedTrustResolverDestroy(request_rec* r, struct oidfed_trust_resolver* rx);

void OIFMayLoad_oidfedTrustResolverDestroy_server(server_rec* sv, struct oidfed_trust_resolver* rx);

struct oidfed_trust_chains OIFMayLoad_oidfedTrustResolverResolveToValidChains(
    request_rec* r, struct oidfed_trust_resolver rx);

struct oidfed_trust_chains OIFMayLoad_oidfedTrustResolverResolveToValidChains_server(
    server_rec* sv, struct oidfed_trust_resolver rx);

size_t OIFMayLoad_oidfedTrustChainsCount(request_rec* r, struct oidfed_trust_chains chains);

size_t OIFMayLoad_oidfedTrustChainsCount_server(server_rec* sv, struct oidfed_trust_chains chains);

struct oidfed_trust_chain OIFMayLoad_oidfedTrustChainsGet(request_rec* r, struct oidfed_trust_chains chains,
                                                          size_t index);

struct oidfed_trust_chain OIFMayLoad_oidfedTrustChainsGet_server(server_rec* sv, struct oidfed_trust_chains chains,
                                                                 size_t index);

void OIFMayLoad_oidfedTrustChainsDestroy(request_rec* r, struct oidfed_trust_chains* chains);

void OIFMayLoad_oidfedTrustChainsDestroy_server(server_rec* sv, struct oidfed_trust_chains* chains);

void OIFMayLoad_oidfedTrustChainDestroy(request_rec* r, struct oidfed_trust_chain* chain);

void OIFMayLoad_oidfedTrustChainDestroy_server(server_rec* sv, struct oidfed_trust_chain* chain);

struct oidfed_metadata OIFMayLoad_oidfedTrustChainGetMetadata(request_rec* r, struct oidfed_trust_chain chain,
                                                              int* errc);

struct oidfed_metadata OIFMayLoad_oidfedTrustChainGetMetadata_server(server_rec* sv, struct oidfed_trust_chain chain,
                                                                     int* errc);

void OIFMayLoad_oidfedMetadataDestroy(request_rec* r, struct oidfed_metadata* m);

void OIFMayLoad_oidfedMetadataDestroy_server(server_rec* sv, struct oidfed_metadata* m);

void OIFMayLoad_oidfedUiInfoDestroy(request_rec* r, struct oidfed_ui_info* ui);

void OIFMayLoad_oidfedUiInfoDestroy_server(server_rec* sv, struct oidfed_ui_info* ui);

#endif
