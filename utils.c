#include "utils.h"

#include <apr_pools.h>
#include <apr_strings.h>
#include <assert.h>
#include <limits.h>

static char
fmtscan_asc(const char c) {
    static char const charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    if (c < 0) return 0;
    if (c >= sizeof(charset) - 1) return 0;

    return charset[c];
}

static size_t
umax_fmt_get_length(const uintmax_t d,
                    const uint8_t base) {
    size_t len = 1;
    uintmax_t q = d;
    while (q >= base) {
        len++;
        q /= base;
    }
    return len;
}

static size_t
umax_fmt_generic(char* out,
                 uintmax_t d,
                 const uint8_t base) {
    const size_t len = umax_fmt_get_length(d, base);
    if (!out) return len;

    out += len;
    do {
        *--out = fmtscan_asc((char) (d % (uintmax_t) base));
        d /= base;
    } while (d);
    return len;
}


static size_t
si_fmt_get_length(const signed int d,
                  const uint8_t base) {
    size_t len = 1;
    signed int q = d;
    while (q >= base) {
        len++;
        q /= base;
    }
    return len;
}

static size_t
si_fmt_generic(char* out,
               signed int d,
               const uint8_t base) {
    assert(d >= 0 && "d must be nonnegative");
    const size_t len = si_fmt_get_length(d, base);
    if (!out) return len;

    out += len;
    do {
        *--out = fmtscan_asc((char) (d % (typeof(d)) base));
        d /= base;
    } while (d);
    return len;
}

size_t
ull_fmt(char* out, const unsigned long long d, const uint8_t base) {
    assert(base >= 2 && base <= 36 && "base must be in [2, 36]");

    return umax_fmt_generic(out, d, base);
}

size_t
ui_fmt(char* out, const unsigned int d, const uint8_t base) {
    assert(base >= 2 && base <= 36 && "base must be in [2, 36]");

    return umax_fmt_generic(out, d, base);
}

size_t
size_fmt(char* out, const size_t d, const uint8_t base) {
    assert(base >= 2 && base <= 36 && "base must be in [2, 36]");

    return umax_fmt_generic(out, d, base);
}

size_t
si_fmt(char* out, const signed int d, const uint8_t base) {
    assert(base >= 2 && base <= 36 && "base must be in [2, 36]");

    if (d >= 0) return si_fmt_generic(out, d, base);
    if (d == INT_MIN) return 1u + umax_fmt_generic(out, ((uintmax_t) INT_MAX) + 1, base);
    if (!out) return 1u + si_fmt_generic(NULL, -d, base);

    *out++ = '-';
    return 1u + si_fmt_generic(out, -d, base);
}

char*
encode_netstring(apr_pool_t* p, const char* str, const size_t str_sz) {
    char num_buf[sizeof("18446744073709551615")] = {0};
    assert(sizeof(size_t) * CHAR_BIT <= 64);

    const size_t buf_len = ull_fmt(num_buf, str_sz, 10);
    num_buf[buf_len] = '\0';

    char* const ret = apr_palloc(p, buf_len + 1 + str_sz + 1 + 1);
    memcpy(ret, num_buf, buf_len);
    ret[buf_len] = ':';
    memcpy(ret + buf_len + 1, str, str_sz);
    ret[buf_len + 1 + str_sz] = ',';
    ret[buf_len + 1 + str_sz + 1] = '\0';

    return ret;
}

char*
encode_netstringc(apr_pool_t* p, const char* str) {
    return encode_netstring(p, str, strlen(str));
}

char*
decode_netstring_inplace(char* buff, char** last) {
    char* colon;

    errno = 0;
    uintmax_t str_szmax = strtoumax(buff, &colon, 10);
    if (buff[0] == '\0' || *colon != ':') goto err_invalid_netstring;
    if (errno == ERANGE && str_szmax == UINTMAX_MAX) goto err_overflow;

    // Try casting into a proper size type. uintmax_t is guaranteed to hold
    // whatever I want to hold, and if it ends up being larger than a size_t, we
    // report an error.
    if (str_szmax > (uintmax_t) SIZE_MAX) goto err_overflow;
    const size_t str_sz = (size_t) str_szmax;

    char* str = colon + 1;
    char* end_of_str = str + str_sz;
    if (*end_of_str != ',') goto err_invalid_netstring;

    *end_of_str = '\0';
    if (last) *last = end_of_str;
    return str;

err_overflow:
    errno = EOVERFLOW;
    return NULL;

err_invalid_netstring:
    errno = EINVAL;
    return NULL;
}
