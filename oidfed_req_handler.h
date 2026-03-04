#ifndef OIDFED_OIDFED_REQ_HANDLER_H
#define OIDFED_OIDFED_REQ_HANDLER_H

#include <ap_config.h>
#include <httpd.h>

#define OIDFED_SESSION_COOKIE "OIDFED_SESSION"

struct oidfed_session {
    char* sid;
    char* op_id;
    char* token_response;
    apr_time_t expiry;
};

struct oidfed_session_storage {
    void* impl;
    void (*set)(const struct oidfed_session_storage* storage, const struct oidfed_session* session);
    struct oidfed_session* (*get)(const struct oidfed_session_storage* storage, const char* sid);
    void (*remove)(const struct oidfed_session_storage* storage, const char* sid);
};

int
oidfed_req_handler(request_rec* r);

int
oidfed_authenticate_user(request_rec* r);

#endif
