#ifndef OIDFED_OIDFED_REQ_HANDLER_H
#define OIDFED_OIDFED_REQ_HANDLER_H

#include <ap_config.h>
#include <httpd/httpd.h>

int
oidfed_req_handler(request_rec* r);

int
oidfed_req_well_known_handler(request_rec* r);

#endif
