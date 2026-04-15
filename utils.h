#ifndef OIDFED_UTILS_H
#define OIDFED_UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <apr_pools.h>

size_t
si_fmt(char* out, signed int d, uint8_t base);

size_t
ui_fmt(char* out, unsigned int d, uint8_t base);

size_t
ull_fmt(char* out, unsigned long long d, uint8_t base);

size_t
size_fmt(char* out, size_t d, uint8_t base);

char*
encode_netstringc(apr_pool_t* p, const char* str);

char*
encode_netstring(apr_pool_t* p, const char* str, size_t str_sz);

char*
decode_netstring_inplace(char* buff, char** last);

#endif
