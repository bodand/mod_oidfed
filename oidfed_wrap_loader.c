#include <ap_config.h>
#include <httpd.h>
#include <http_log.h>

#include <assert.h>
#include <dlfcn.h>

#include <oidfed_wrap_loader.h>
#include <oidfed_config.h>

#ifndef MOD_OIDFED_OIDFED_LOADER_COMMON_H
#define MOD_OIDFED_OIDFED_LOADER_COMMON_H

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
            logger(APLOG_MARK, APLOG_EMERG, __VA_ARGS__, \
                        "oidfedWrap: symbol called without initialization! " \
                        "This is likely a result of earlier errors."); \
            assert(false && "module invariant broken: oidfed_worker_init() not called"); \
        } \
        void* sym = dlsym(dynlib, APR_STRINGIFY(fn)); \
        if (UNLIKELY(!sym)) { \
            logger(APLOG_MARK, APLOG_EMERG, __VA_ARGS__, \
                "oidfedWrap: symbol '%s' is not found in wrap library. " \
                "This is likely a result of a currepted or drifted installation.", \
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
    OIDFED_MAYLOAD_FOR_REQUEST(wrap_request_ctx, fn); \
    ret OIDFED_CAT(OIDFED_FN_HOLDER_PREFIX, fn)

#define OIDFED_MAYLOAD_SERVER(ret, fn) \
    OIDFED_MAYLOAD_ON_INIT(wrap_server_ctx, fn); \
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

#endif

#include "oidfed_wrap_loader.gen.c"

