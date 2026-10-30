#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

/* The remaining request-level buffered bit (the core uses 0x01..0x04). */
#define HLS_BUFFERED 0x08
#define HLS_LINES 2
#define HLS_KEYS 4
#define HLS_MAPS 8
#define HLS_MEDIA 16
#define HLS_ALL (HLS_LINES | HLS_KEYS | HLS_MAPS | HLS_MEDIA)

typedef struct {
    ngx_str_t name;
    ngx_http_complex_value_t value;
} hls_param_t;

typedef struct {
    ngx_str_t literal;
    ngx_int_t index;
} hls_sign_part_t;

typedef struct {
    ngx_flag_t auth, rewrite, resign;
    ngx_uint_t algorithm, encoding, time_mode, resources;
    ngx_http_complex_value_t *token, *message, *key, *timestamp, *bind_ip;
    ngx_http_complex_value_t *sign_message, *sign_playlist_message, *public_origin;
    ngx_array_t *sign_parts, *sign_playlist_parts;
    ngx_str_t sign_param;
    time_t ttl, skew;
    size_t line_size;
    ngx_array_t *required, *params, *origins, *types;
} hls_conf_t;

typedef struct {
    ngx_str_t name, value;
    ngx_uint_t count;
} hls_arg_t;

typedef struct {
    ngx_array_t args;
    ngx_str_t status, query;
    ngx_str_t target, target_path, signing_key, origin;
    ngx_uint_t target_active, origin_ready;
    ngx_uint_t parsed, bad_args, active, seen_magic, finished;
    ngx_chain_t *in, *free, *busy, *pending;
    u_char *line;
    size_t len;
    ngx_pool_t *scratch;
} hls_ctx_t;

static ngx_int_t hls_init(ngx_conf_t *cf);
static ngx_int_t hls_variables(ngx_conf_t *cf);
static void *hls_create(ngx_conf_t *cf);
static char *hls_merge(ngx_conf_t *cf, void *parent, void *child);
static char *hls_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *hls_param(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *hls_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_array_t *hls_compile_sign(ngx_conf_t *cf, ngx_str_t text);
static ngx_int_t hls_target_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t hls_access(ngx_http_request_t *r);
static ngx_int_t hls_header(ngx_http_request_t *r);
static ngx_int_t hls_body(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t hls_arg_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t hls_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t hls_origin(ngx_pool_t *pool, ngx_str_t *url,
    ngx_str_t *origin, size_t *end, ngx_flag_t https);

static ngx_http_output_header_filter_pt hls_next_header;
static ngx_http_output_body_filter_pt hls_next_body;

static ngx_conf_enum_t hls_algorithms[] = {
    { ngx_string("md5"), 0 }, { ngx_string("sha256"), 1 },
    { ngx_string("hmac_sha256"), 2 }, { ngx_null_string, 0 }
};
static ngx_conf_enum_t hls_encodings[] = {
    { ngx_string("hex"), 0 }, { ngx_string("base64"), 1 },
    { ngx_string("base64url"), 2 }, { ngx_null_string, 0 }
};
static ngx_conf_enum_t hls_times[] = {
    { ngx_string("off"), 0 }, { ngx_string("issued"), 1 },
    { ngx_string("expires"), 2 }, { ngx_null_string, 0 }
};
static ngx_conf_bitmask_t hls_resources[] = {
    { ngx_string("lines"), HLS_LINES }, { ngx_string("keys"), HLS_KEYS },
    { ngx_string("maps"), HLS_MAPS }, { ngx_string("media"), HLS_MEDIA },
    { ngx_string("all"), HLS_ALL }, { ngx_string("none"), 32 },
    { ngx_null_string, 0 }
};

#define HLS_CONTEXT (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF)
#define HLS_CMD(name, flags, setter, field, post) \
    { ngx_string(name), HLS_CONTEXT|flags, setter, NGX_HTTP_LOC_CONF_OFFSET, \
      offsetof(hls_conf_t, field), post }

static ngx_command_t hls_commands[] = {
    HLS_CMD("secure_hls_auth", NGX_CONF_FLAG, ngx_conf_set_flag_slot, auth, NULL),
    HLS_CMD("secure_hls_rewrite", NGX_CONF_FLAG, ngx_conf_set_flag_slot, rewrite, NULL),
    HLS_CMD("secure_hls_resign", NGX_CONF_FLAG, ngx_conf_set_flag_slot, resign, NULL),
    HLS_CMD("secure_hls_sign_param", NGX_CONF_TAKE1, ngx_conf_set_str_slot, sign_param, NULL),
    HLS_CMD("secure_hls_sign_message", NGX_CONF_TAKE1, ngx_http_set_complex_value_slot, sign_message, NULL),
    HLS_CMD("secure_hls_sign_playlist_message", NGX_CONF_TAKE1, ngx_http_set_complex_value_slot, sign_playlist_message, NULL),
    HLS_CMD("secure_hls_public_origin", NGX_CONF_TAKE1, ngx_http_set_complex_value_slot, public_origin, NULL),
    HLS_CMD("secure_hls_algorithm", NGX_CONF_TAKE1, ngx_conf_set_enum_slot, algorithm, hls_algorithms),
    HLS_CMD("secure_hls_encoding", NGX_CONF_TAKE1, ngx_conf_set_enum_slot, encoding, hls_encodings),
    HLS_CMD("secure_hls_time_mode", NGX_CONF_TAKE1, ngx_conf_set_enum_slot, time_mode, hls_times),
    HLS_CMD("secure_hls_token", NGX_CONF_TAKE1, ngx_http_set_complex_value_slot, token, NULL),
    HLS_CMD("secure_hls_message", NGX_CONF_TAKE1, ngx_http_set_complex_value_slot, message, NULL),
    HLS_CMD("secure_hls_hmac_key", NGX_CONF_TAKE1, ngx_http_set_complex_value_slot, key, NULL),
    HLS_CMD("secure_hls_timestamp", NGX_CONF_TAKE1, ngx_http_set_complex_value_slot, timestamp, NULL),
    HLS_CMD("secure_hls_bind_ip", NGX_CONF_TAKE1, hls_bind, bind_ip, NULL),
    HLS_CMD("secure_hls_ttl", NGX_CONF_TAKE1, ngx_conf_set_sec_slot, ttl, NULL),
    HLS_CMD("secure_hls_clock_skew", NGX_CONF_TAKE1, ngx_conf_set_sec_slot, skew, NULL),
    HLS_CMD("secure_hls_max_line", NGX_CONF_TAKE1, ngx_conf_set_size_slot, line_size, NULL),
    HLS_CMD("secure_hls_require_args", NGX_CONF_1MORE, hls_list, required, NULL),
    HLS_CMD("secure_hls_allowed_origin", NGX_CONF_1MORE, hls_list, origins, NULL),
    HLS_CMD("secure_hls_types", NGX_CONF_1MORE, hls_list, types, NULL),
    HLS_CMD("secure_hls_resources", NGX_CONF_1MORE, ngx_conf_set_bitmask_slot, resources, hls_resources),
    HLS_CMD("secure_hls_param", NGX_CONF_TAKE2, hls_param, params, NULL),
    ngx_null_command
};

static ngx_http_module_t hls_module_ctx = {
    hls_variables, hls_init, NULL, NULL, NULL, NULL, hls_create, hls_merge
};

ngx_module_t ngx_http_secure_hls_module = {
    NGX_MODULE_V1, &hls_module_ctx, hls_commands, NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NGX_MODULE_V1_PADDING
};

static ngx_int_t
hls_equal(ngx_str_t a, ngx_str_t b)
{
    return a.len == b.len && (a.len == 0 || ngx_memcmp(a.data, b.data, a.len) == 0);
}

static ngx_int_t
hls_name(ngx_str_t s)
{
    size_t i;
    if (s.len == 0) { return 0; }
    for (i = 0; i < s.len; i++) {
        if (!((s.data[i] >= 'a' && s.data[i] <= 'z')
              || (s.data[i] >= '0' && s.data[i] <= '9')
              || s.data[i] == '_')) { return 0; }
    }
    return 1;
}

static char *
hls_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_array_t **a = (ngx_array_t **) ((u_char *) conf + cmd->offset);
    ngx_str_t *v = cf->args->elts, *s, norm;
    ngx_uint_t i;
    size_t end;
    if (*a == NGX_CONF_UNSET_PTR) {
        *a = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (*a == NULL) { return NGX_CONF_ERROR; }
    }
    for (i = 1; i < cf->args->nelts; i++) {
        if (cmd->offset == offsetof(hls_conf_t, required) && !hls_name(v[i])) {
            return "requires lowercase argument names using a-z, 0-9, underscore";
        }
        norm = v[i];
        if (cmd->offset == offsetof(hls_conf_t, origins)) {
            if (hls_origin(cf->pool, &v[i], &norm, &end, 0) != NGX_OK
                || end != v[i].len || v[i].len < 8
                || ngx_strncmp(v[i].data, "//", 2) == 0)
            {
                return "requires an exact http(s) origin without path/query";
            }
        }
        s = ngx_array_push(*a);
        if (s == NULL) { return NGX_CONF_ERROR; }
        *s = norm;
    }
    return NGX_CONF_OK;
}

static char *
hls_param(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    hls_conf_t *c = conf;
    ngx_str_t *v = cf->args->elts;
    hls_param_t *p;
    ngx_uint_t i;
    ngx_http_compile_complex_value_t ccv;
    (void) cmd;
    if (!hls_name(v[1])) { return "requires a lowercase output argument name"; }
    if (c->params == NGX_CONF_UNSET_PTR) {
        c->params = ngx_array_create(cf->pool, 4, sizeof(hls_param_t));
        if (c->params == NULL) { return NGX_CONF_ERROR; }
    }
    p = c->params->elts;
    for (i = 0; i < c->params->nelts; i++) {
        if (hls_equal(p[i].name, v[1])) { return "has a duplicate output argument"; }
    }
    p = ngx_array_push(c->params);
    if (p == NULL) { return NGX_CONF_ERROR; }
    p->name = v[1];
    ngx_memzero(&ccv, sizeof(ccv));
    ccv.cf = cf; ccv.value = &v[2]; ccv.complex_value = &p->value;
    return ngx_http_compile_complex_value(&ccv) == NGX_OK ? NGX_CONF_OK : NGX_CONF_ERROR;
}

static char *
hls_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    hls_conf_t *c = conf;
    ngx_str_t *v = cf->args->elts, name;
    if (v[1].len == 3 && ngx_strncmp(v[1].data, "off", 3) == 0) {
        if (c->bind_ip != NGX_CONF_UNSET_PTR) { return "is duplicate"; }
        c->bind_ip = NULL;
        return NGX_CONF_OK;
    }
    if (v[1].len <= 16 || ngx_strncmp(v[1].data, "$secure_hls_arg_", 16) != 0) {
        return "requires off or a single $secure_hls_arg_* variable";
    }
    name.data = v[1].data + 16; name.len = v[1].len - 16;
    if (!hls_name(name)) { return "requires a single argument variable"; }
    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}

static void *
hls_create(ngx_conf_t *cf)
{
    hls_conf_t *c = ngx_pcalloc(cf->pool, sizeof(*c));
    if (c == NULL) { return NULL; }
    c->auth = c->rewrite = NGX_CONF_UNSET;
    c->resign = NGX_CONF_UNSET;
    c->algorithm = c->encoding = c->time_mode = NGX_CONF_UNSET_UINT;
    c->ttl = c->skew = NGX_CONF_UNSET;
    c->line_size = NGX_CONF_UNSET_SIZE;
    c->token = c->message = c->key = c->timestamp = c->bind_ip = NGX_CONF_UNSET_PTR;
    c->sign_message = c->sign_playlist_message = c->public_origin = NGX_CONF_UNSET_PTR;
    c->required = c->params = c->origins = c->types = NGX_CONF_UNSET_PTR;
    return c;
}

/* Check complete variable references, not string substrings. */
static ngx_int_t
hls_references(ngx_str_t text, ngx_str_t name)
{
    size_t i, start, n;
    ngx_uint_t braces;
    for (i = 0; i < text.len; i++) {
        if (text.data[i] != '$') { continue; }
        start = ++i; braces = 0;
        if (i < text.len && text.data[i] == '{') { braces = 1; start = ++i; }
        while (i < text.len && ((text.data[i] >= 'a' && text.data[i] <= 'z')
               || (text.data[i] >= 'A' && text.data[i] <= 'Z')
               || (text.data[i] >= '0' && text.data[i] <= '9')
               || text.data[i] == '_')) { i++; }
        n = i - start;
        if (n == name.len && ngx_memcmp(text.data + start, name.data, n) == 0
            && (!braces || (i < text.len && text.data[i] == '}'))) { return 1; }
        if (i > 0) { i--; }
    }
    return 0;
}

static char *
hls_merge(ngx_conf_t *cf, void *parent, void *child)
{
    hls_conf_t *p = parent, *c = child;
    ngx_str_t name, target_name = ngx_string("secure_hls_target");
    ngx_str_t filename_name = ngx_string("secure_hls_target_filename");
    ngx_str_t path_name = ngx_string("secure_hls_target_path");
    hls_param_t *params;
    ngx_uint_t i;
    ngx_conf_merge_value(c->auth, p->auth, 0);
    ngx_conf_merge_value(c->rewrite, p->rewrite, 0);
    ngx_conf_merge_value(c->resign, p->resign, 0);
    ngx_conf_merge_str_value(c->sign_param, p->sign_param, "");
    ngx_conf_merge_ptr_value(c->sign_message, p->sign_message, NULL);
    ngx_conf_merge_ptr_value(c->sign_playlist_message, p->sign_playlist_message, NULL);
    ngx_conf_merge_ptr_value(c->public_origin, p->public_origin, NULL);
    ngx_conf_merge_uint_value(c->algorithm, p->algorithm, NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(c->encoding, p->encoding, 0);
    ngx_conf_merge_uint_value(c->time_mode, p->time_mode, 0);
    ngx_conf_merge_sec_value(c->ttl, p->ttl, 7200);
    ngx_conf_merge_sec_value(c->skew, p->skew, 30);
    ngx_conf_merge_size_value(c->line_size, p->line_size, 65536);
    ngx_conf_merge_bitmask_value(c->resources, p->resources, HLS_ALL);
    ngx_conf_merge_ptr_value(c->token, p->token, NULL);
    ngx_conf_merge_ptr_value(c->message, p->message, NULL);
    ngx_conf_merge_ptr_value(c->key, p->key, NULL);
    ngx_conf_merge_ptr_value(c->timestamp, p->timestamp, NULL);
    ngx_conf_merge_ptr_value(c->bind_ip, p->bind_ip, NULL);
    ngx_conf_merge_ptr_value(c->required, p->required, NULL);
    ngx_conf_merge_ptr_value(c->params, p->params, NULL);
    ngx_conf_merge_ptr_value(c->origins, p->origins, NULL);
    ngx_conf_merge_ptr_value(c->types, p->types, NULL);
    if (c->line_size < 128 || c->line_size > 16 * 1024 * 1024) {
        return "secure_hls_max_line must be between 128 and 16m";
    }
    if ((c->resources & 32) && (c->resources & HLS_ALL)) {
        return "secure_hls_resources none cannot be combined with other types";
    }
    if (c->auth && (c->algorithm == NGX_CONF_UNSET_UINT || c->token == NULL
                   || c->message == NULL))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "secure_hls_auth requires algorithm, token and message");
        return NGX_CONF_ERROR;
    }
    if (c->auth && c->algorithm == 2 && c->key == NULL) {
        return "secure_hls_hmac_key is required for hmac_sha256";
    }
    if (c->auth && c->time_mode && c->timestamp == NULL) {
        return "secure_hls_timestamp is required for time validation";
    }
    if (c->auth && c->time_mode == 1 && c->ttl == 0) {
        return "secure_hls_ttl must be positive in issued mode";
    }
    if (c->auth && c->bind_ip) {
        name = c->bind_ip->value; name.data++; name.len--;
        if (!hls_references(c->message->value, name)) {
            return "secure_hls_message must directly reference the bound IP variable";
        }
    }
    if (c->resign) {
        if (!c->auth || !hls_name(c->sign_param)
            || c->sign_message == NULL || c->sign_playlist_message == NULL)
        {
            return "secure_hls_resign requires auth, sign_param and both signing messages";
        }
        if ((!hls_references(c->sign_message->value, target_name)
             && !hls_references(c->sign_message->value, filename_name)
             && !hls_references(c->sign_message->value, path_name))
            || !hls_references(c->sign_playlist_message->value, path_name))
        {
            return "signing messages must bind a target variable, and target_path for playlists";
        }
        if (c->params) {
            params = c->params->elts;
            for (i = 0; i < c->params->nelts; i++) {
                if (hls_equal(params[i].name, c->sign_param))
                { return "secure_hls_param conflicts with a generated signing argument"; }
            }
        }
        c->sign_parts = hls_compile_sign(cf, c->sign_message->value);
        c->sign_playlist_parts = hls_compile_sign(cf, c->sign_playlist_message->value);
        if (c->sign_parts == NULL || c->sign_playlist_parts == NULL) { return NGX_CONF_ERROR; }
    }
    return NGX_CONF_OK;
}

static hls_ctx_t *
hls_context(ngx_http_request_t *r)
{
    hls_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_secure_hls_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) { return NULL; }
        ngx_str_set(&ctx->status, "off");
        ngx_http_set_ctx(r, ctx, ngx_http_secure_hls_module);
    }
    return ctx;
}

static ngx_int_t
hls_decode(ngx_pool_t *pool, ngx_str_t in, ngx_str_t *out)
{
    u_char *d, ch;
    ngx_int_t hex;
    size_t i;
    out->data = ngx_pnalloc(pool, in.len + 1);
    if (out->data == NULL) { return NGX_ERROR; }
    d = out->data;
    for (i = 0; i < in.len; i++) {
        ch = in.data[i];
        if (ch == '%') {
            if (i + 2 >= in.len) { return NGX_DECLINED; }
            hex = ngx_hextoi(in.data + i + 1, 2);
            if (hex == NGX_ERROR) { return NGX_DECLINED; }
            ch = (u_char) hex; i += 2;
        } else if (ch == '+') { ch = ' '; }
        if (ch < 0x20 || ch == 0x7f) { return NGX_DECLINED; }
        *d++ = ch;
    }
    out->len = d - out->data; *d = 0;
    return NGX_OK;
}

static ngx_int_t
hls_parse_args(ngx_http_request_t *r, hls_ctx_t *ctx)
{
    u_char *p, *end, *amp, *eq;
    ngx_str_t raw, name, value;
    ngx_int_t rc;
    hls_arg_t *a;
    ngx_uint_t i;
    if (ctx->parsed) { return ctx->bad_args == 2 ? NGX_ERROR : NGX_OK; }
    ctx->parsed = 1;
    if (ngx_array_init(&ctx->args, r->pool, 8, sizeof(hls_arg_t)) != NGX_OK) {
        ctx->bad_args = 2; return NGX_ERROR;
    }
    if (r->args.len == 0) { return NGX_OK; }
    p = r->args.data; end = p + r->args.len;
    while (p < end) {
        amp = ngx_strlchr(p, end, '&'); if (amp == NULL) { amp = end; }
        if (amp == p) { p++; continue; }
        eq = ngx_strlchr(p, amp, '='); if (eq == NULL) { eq = amp; }
        raw.data = p; raw.len = eq - p;
        rc = hls_decode(r->pool, raw, &name);
        if (rc != NGX_OK) { ctx->bad_args = rc == NGX_ERROR ? 2 : 1; return rc == NGX_ERROR ? rc : NGX_OK; }
        raw.data = eq < amp ? eq + 1 : amp; raw.len = amp - raw.data;
        rc = hls_decode(r->pool, raw, &value);
        if (rc != NGX_OK) { ctx->bad_args = rc == NGX_ERROR ? 2 : 1; return rc == NGX_ERROR ? rc : NGX_OK; }
        a = ctx->args.elts;
        for (i = 0; i < ctx->args.nelts; i++) {
            if (hls_equal(a[i].name, name)) { a[i].count++; break; }
        }
        if (i == ctx->args.nelts) {
            a = ngx_array_push(&ctx->args);
            if (a == NULL) { ctx->bad_args = 2; return NGX_ERROR; }
            a->name = name; a->value = value; a->count = 1;
        }
        p = amp < end ? amp + 1 : end;
    }
    return NGX_OK;
}

static ngx_int_t
hls_lookup(ngx_http_request_t *r, hls_ctx_t *ctx, ngx_str_t name, ngx_str_t *value)
{
    hls_arg_t *a;
    ngx_uint_t i;
    if (hls_parse_args(r, ctx) != NGX_OK) { return NGX_ERROR; }
    a = ctx->args.elts;
    for (i = 0; i < ctx->args.nelts; i++) {
        if (hls_equal(a[i].name, name)) {
            if (a[i].count != 1) { ctx->bad_args = 1; return NGX_DECLINED; }
            *value = a[i].value; return NGX_OK;
        }
    }
    return NGX_DECLINED;
}

static ngx_int_t
hls_arg_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t name = *(ngx_str_t *) data, value;
    hls_ctx_t *ctx = hls_context(r);
    ngx_int_t rc;
    if (ctx == NULL) { return NGX_ERROR; }
    name.data += 15; name.len -= 15; /* secure_hls_arg_ */
    rc = hls_lookup(r, ctx, name, &value);
    if (rc == NGX_ERROR) { return NGX_ERROR; }
    if (rc != NGX_OK) { v->not_found = 1; return NGX_OK; }
    v->data = value.data; v->len = value.len;
    v->valid = 1; v->not_found = 0; v->no_cacheable = 1;
    return NGX_OK;
}

static ngx_int_t
hls_status_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    hls_ctx_t *ctx = hls_context(r);
    (void) data;
    if (ctx == NULL) { return NGX_ERROR; }
    v->data = ctx->status.data; v->len = ctx->status.len;
    v->valid = 1; v->not_found = 0; v->no_cacheable = 1;
    return NGX_OK;
}

static ngx_int_t
hls_fail(hls_ctx_t *ctx, const char *status, ngx_int_t code)
{
    ctx->status.data = (u_char *) status;
    ctx->status.len = ngx_strlen(status);
    return code;
}

static ngx_int_t
hls_playlist_path(ngx_http_request_t *r)
{
    return r->uri.len >= 5
        && ngx_strncasecmp(r->uri.data + r->uri.len - 5, (u_char *) ".m3u8", 5) == 0;
}

static ngx_int_t
hls_digest(ngx_uint_t algorithm, ngx_str_t key, ngx_str_t message,
    u_char *digest, unsigned int *len)
{
    const EVP_MD *md = algorithm == 0 ? EVP_md5() : EVP_sha256();
    EVP_MD_CTX *mdctx;
    ngx_int_t rc;
    if (algorithm == 2) {
        if (key.len == 0 || key.len > INT_MAX) { return NGX_ERROR; }
        return HMAC(md, key.data, (int) key.len, message.data, message.len,
                    digest, len) ? NGX_OK : NGX_ERROR;
    }
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) { return NGX_ERROR; }
    rc = EVP_DigestInit_ex(mdctx, md, NULL) == 1
        && EVP_DigestUpdate(mdctx, message.data, message.len) == 1
        && EVP_DigestFinal_ex(mdctx, digest, len) == 1;
    EVP_MD_CTX_free(mdctx);
    return rc ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
hls_access(ngx_http_request_t *r)
{
    hls_conf_t *c = ngx_http_get_module_loc_conf(r, ngx_http_secure_hls_module);
    hls_ctx_t *ctx;
    ngx_str_t token, message, key = ngx_null_string, decoded, canon, val, *names;
    ngx_uint_t i;
    ngx_int_t rc, h;
    time_t stamp, now;
    unsigned int n;
    u_char digest[EVP_MAX_MD_SIZE], received[EVP_MAX_MD_SIZE], encoded[128];
    ngx_addr_t addr;

    if (!c->auth && !c->rewrite) { return NGX_DECLINED; }
    ctx = hls_context(r); if (ctx == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    /* Suppress client validators before upstream header construction. */
    if (c->rewrite) {
        /* MIME-only detection happens after the core not-modified filter. */
        r->disable_not_modified = 1;
    }
    if (c->rewrite && hls_playlist_path(r)) {
        r->headers_in.if_modified_since = NULL;
        r->headers_in.if_unmodified_since = NULL;
        r->headers_in.if_none_match = NULL;
        r->headers_in.if_match = NULL;
        r->headers_in.if_range = NULL;
        r->headers_in.range = NULL;
    }
    if (!c->auth) { return NGX_DECLINED; }
    if (hls_parse_args(r, ctx) != NGX_OK) { goto internal; }
    if (ctx->bad_args) { goto bad_args; }
    if (c->required) {
        names = c->required->elts;
        for (i = 0; i < c->required->nelts; i++) {
            rc = hls_lookup(r, ctx, names[i], &val);
            if (rc == NGX_ERROR) { goto internal; }
            if (rc != NGX_OK || val.len == 0) {
                return hls_fail(ctx, "missing_argument", NGX_HTTP_FORBIDDEN);
            }
        }
    }
    if (ngx_http_complex_value(r, c->token, &token) != NGX_OK
        || ngx_http_complex_value(r, c->message, &message) != NGX_OK) { goto internal; }
    if (ctx->bad_args) { goto bad_args; }
    n = c->algorithm == 0 ? 16 : 32;
    if (c->encoding == 0) {
        if (token.len != n * 2) { goto signature; }
        for (i = 0; i < n; i++) {
            h = ngx_hextoi(token.data + i * 2, 2);
            if (h == NGX_ERROR) { goto signature; }
            received[i] = (u_char) h;
        }
    } else {
        if (token.len > 88 || token.len == 0) { goto signature; }
        decoded.data = received;
        /* Bound decoded writes before using nginx's decoder. */
        if (ngx_base64_decoded_length(token.len) > sizeof(received)) { goto signature; }
        rc = c->encoding == 1 ? ngx_decode_base64(&decoded, &token)
                              : ngx_decode_base64url(&decoded, &token);
        if (rc != NGX_OK || decoded.len != n) { goto signature; }
        canon.data = encoded;
        if (c->encoding == 1) { ngx_encode_base64(&canon, &decoded); }
        else { ngx_encode_base64url(&canon, &decoded); }
        if (!hls_equal(canon, token)) { goto signature; }
    }
    if (c->algorithm == 2) {
        if (ngx_http_complex_value(r, c->key, &key) != NGX_OK) { goto internal; }
        if (ctx->bad_args) { goto bad_args; }
    }
    if (hls_digest(c->algorithm, key, message, digest, &n) != NGX_OK) { goto internal; }
    if (CRYPTO_memcmp(digest, received, n) != 0) { goto signature; }
    if (c->time_mode) {
        if (ngx_http_complex_value(r, c->timestamp, &val) != NGX_OK) { goto internal; }
        if (ctx->bad_args) { goto bad_args; }
        stamp = ngx_atotm(val.data, val.len); now = ngx_time();
        if (stamp == NGX_ERROR) { return hls_fail(ctx, "invalid_time", NGX_HTTP_FORBIDDEN); }
        if (c->time_mode == 1) {
            if (stamp > now && stamp - now > c->skew) {
                return hls_fail(ctx, "future_time", NGX_HTTP_FORBIDDEN);
            }
            if (now >= stamp && now - stamp > c->ttl
                && now - stamp - c->ttl > c->skew)
            {
                return hls_fail(ctx, "expired", NGX_HTTP_FORBIDDEN);
            }
        } else if (now > stamp && now - stamp > c->skew) {
            return hls_fail(ctx, "expired", NGX_HTTP_FORBIDDEN);
        }
    }
    if (c->bind_ip) {
        if (ngx_http_complex_value(r, c->bind_ip, &val) != NGX_OK) { goto internal; }
        if (ctx->bad_args) { goto bad_args; }
        rc = ngx_parse_addr(r->pool, &addr, val.data, val.len);
        if (rc == NGX_ERROR) { goto internal; }
        if (rc != NGX_OK || ngx_cmp_sockaddr(addr.sockaddr, addr.socklen,
             r->connection->sockaddr, r->connection->socklen, 0) != NGX_OK)
        {
            return hls_fail(ctx, "ip_mismatch", NGX_HTTP_FORBIDDEN);
        }
    }
    ngx_str_set(&ctx->status, "ok");
    return NGX_DECLINED;
bad_args:
    return hls_fail(ctx, "invalid_arguments", NGX_HTTP_FORBIDDEN);
signature:
    return hls_fail(ctx, "invalid_signature", NGX_HTTP_FORBIDDEN);
internal:
    return hls_fail(ctx, "internal_error", NGX_HTTP_INTERNAL_SERVER_ERROR);
}

/* Canonical exact origin. Never accept userinfo, escaped hosts or backslashes. */
static ngx_int_t
hls_origin(ngx_pool_t *pool, ngx_str_t *url, ngx_str_t *origin,
    size_t *end, ngx_flag_t https)
{
    size_t start, stop, host_end, port_at, i;
    ngx_int_t port;
    u_char *d;
    ngx_str_t host;
    ngx_addr_t addr;
    if (url->len >= 7 && ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        start = 7; https = 0;
    } else if (url->len >= 8 && ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {
        start = 8; https = 1;
    } else if (url->len >= 2 && url->data[0] == '/' && url->data[1] == '/') {
        start = 2;
    } else { return NGX_DECLINED; }
    stop = start;
    while (stop < url->len && url->data[stop] != '/' && url->data[stop] != '?'
           && url->data[stop] != '#') { stop++; }
    if (stop == start) { return NGX_DECLINED; }
    *end = stop; host_end = stop; port_at = stop;
    if (url->data[start] == '[') {
        for (i = start + 1; i < stop && url->data[i] != ']'; i++) { /* scan */ }
        if (i == stop) { return NGX_DECLINED; }
        host.data = url->data + start + 1; host.len = i - start - 1;
        if (ngx_parse_addr(pool, &addr, host.data, host.len) != NGX_OK) { return NGX_DECLINED; }
        host_end = i + 1;
        if (host_end != stop) {
            if (url->data[host_end] != ':') { return NGX_DECLINED; }
            port_at = host_end + 1;
        }
    } else {
        for (i = start; i < stop; i++) {
            if (url->data[i] == ':') { host_end = i; port_at = i + 1; break; }
            if (!((url->data[i] >= 'a' && url->data[i] <= 'z')
                  || (url->data[i] >= 'A' && url->data[i] <= 'Z')
                  || (url->data[i] >= '0' && url->data[i] <= '9')
                  || url->data[i] == '.' || url->data[i] == '-')) { return NGX_DECLINED; }
        }
    }
    if (host_end == start) { return NGX_DECLINED; }
    port = https ? 443 : 80;
    if (host_end < stop) {
        port = ngx_atoi(url->data + port_at, stop - port_at);
        if (port < 1 || port > 65535) { return NGX_DECLINED; }
    }
    origin->data = ngx_pnalloc(pool, stop + 16);
    if (origin->data == NULL) { return NGX_ERROR; }
    d = origin->data;
    if (https) { d = ngx_cpymem(d, "https://", 8); }
    else { d = ngx_cpymem(d, "http://", 7); }
    ngx_strlow(d, url->data + start, host_end - start); d += host_end - start;
    if (port != (https ? 443 : 80)) { d = ngx_sprintf(d, ":%i", port); }
    origin->len = d - origin->data;
    return NGX_OK;
}

static ngx_int_t
hls_public_origin(ngx_http_request_t *r, hls_conf_t *c, ngx_str_t *origin)
{
    hls_ctx_t *ctx = hls_context(r);
    ngx_str_t raw, host;
    ngx_flag_t https = 0;
    ngx_int_t rc;
    size_t end;
    if (ctx == NULL) { return NGX_ERROR; }
    if (ctx->origin_ready) { *origin = ctx->origin; return NGX_OK; }
#if (NGX_HTTP_SSL)
    https = r->connection->ssl != NULL;
#endif
    if (c->public_origin) {
        if (ngx_http_complex_value(r, c->public_origin, &raw) != NGX_OK) { return NGX_ERROR; }
    } else {
        host = r->headers_in.host ? r->headers_in.host->value : r->headers_in.server;
        if (host.len == 0) {
            /* HTTP/1.0 without Host still supports relative references. */
            ctx->origin_ready = 1; *origin = ctx->origin;
            return NGX_OK;
        }
        raw.len = host.len + 2; raw.data = ngx_pnalloc(r->pool, raw.len);
        if (raw.data == NULL) { return NGX_ERROR; }
        ngx_memcpy(raw.data, "//", 2); ngx_memcpy(raw.data + 2, host.data, host.len);
    }
    rc = hls_origin(r->pool, &raw, &ctx->origin, &end, https);
    if (rc != NGX_OK || end != raw.len) { return NGX_ERROR; }
    ctx->origin_ready = 1; *origin = ctx->origin;
    return NGX_OK;
}

/* Resolve a URI to the same decoded/normalized path nginx sees on a request.
 * The raw reference remains separately available to configurable templates. */
static ngx_int_t
hls_resolve(ngx_http_request_t *r, hls_conf_t *c, ngx_pool_t *pool,
    ngx_str_t parent, ngx_str_t ref, ngx_str_t *path, ngx_str_t *origin)
{
    ngx_str_t own, raw;
    ngx_http_request_t parsed;
    ngx_int_t rc;
    size_t start = 0, prefix = 0, i;
    u_char *d;
    if (parent.len == 0 || parent.data[0] != '/' || ref.len == 0) { return NGX_DECLINED; }
    for (i = 0; i < parent.len; i++) {
        if (parent.data[i] < 0x20 || parent.data[i] == 0x7f || parent.data[i] == '\\') { return NGX_DECLINED; }
    }
    for (i = 0; i < ref.len; i++) {
        if (ref.data[i] <= 0x20 || ref.data[i] == 0x7f || ref.data[i] == '\\'
            || ref.data[i] == '?' || ref.data[i] == '#') { return NGX_DECLINED; }
    }
    if (hls_public_origin(r, c, &own) != NGX_OK) { return NGX_ERROR; }
    rc = hls_origin(pool, &ref, origin, &start,
                    own.len >= 8 && ngx_strncmp(own.data, "https://", 8) == 0);
    if (rc == NGX_ERROR) { return rc; }
    if (rc == NGX_DECLINED) {
        ngx_str_null(origin); start = 0;
        if (ref.len >= 2 && ref.data[0] == '/' && ref.data[1] == '/') { return NGX_DECLINED; }
        for (i = 0; i < ref.len && ref.data[i] != '/'; i++) {
            if (ref.data[i] == ':') { return NGX_DECLINED; }
        }
        if (ref.data[0] != '/') {
            for (i = parent.len; i > 0; i--) {
                if (parent.data[i - 1] == '/') { prefix = i; break; }
            }
        }
    }
    raw.data = ngx_pnalloc(pool, prefix * 3 + ref.len + 2);
    if (raw.data == NULL) { return NGX_ERROR; }
    /* Escape the already-decoded parent before feeding nginx's URI parser. */
    d = raw.data;
    if (prefix) {
        d = (u_char *) ngx_escape_uri(d, parent.data, prefix, NGX_ESCAPE_URI);
    }
    if (start == ref.len) { *d++ = '/'; }
    else { d = ngx_cpymem(d, ref.data + start, ref.len - start); }
    raw.len = d - raw.data; *d = '\n';
    ngx_memzero(&parsed, sizeof(parsed));
    parsed.connection = r->connection;
    parsed.uri_start = raw.data; parsed.uri_end = d;
    parsed.uri.data = ngx_pnalloc(pool, raw.len + 1); parsed.uri.len = raw.len;
    if (parsed.uri.data == NULL) { return NGX_ERROR; }
    if (ngx_http_parse_complex_uri(&parsed, 1) != NGX_OK) { return NGX_DECLINED; }
    for (i = 0; i < parsed.uri.len; i++) {
        if (parsed.uri.data[i] < 0x20 || parsed.uri.data[i] == 0x7f
            || parsed.uri.data[i] == '\\') { return NGX_DECLINED; }
    }
    *path = parsed.uri;
    return NGX_OK;
}

static ngx_int_t
hls_allowed(ngx_http_request_t *r, hls_conf_t *c, ngx_pool_t *pool, ngx_str_t uri)
{
    ngx_str_t origin, own, *allowed;
    size_t i, end;
    ngx_int_t rc;
    if (hls_public_origin(r, c, &own) != NGX_OK) { return NGX_ERROR; }
    rc = hls_origin(pool, &uri, &origin, &end,
                    own.len >= 8 && ngx_strncmp(own.data, "https://", 8) == 0);
    if (rc == NGX_ERROR) { return NGX_ERROR; }
    if (rc == NGX_DECLINED) {
        if (uri.len >= 2 && uri.data[0] == '/' && uri.data[1] == '/') { return NGX_DECLINED; }
        /* A colon in the first path component identifies a URI scheme. */
        for (i = 0; i < uri.len && uri.data[i] != '/' && uri.data[i] != '?'
             && uri.data[i] != '#'; i++) {
            if (uri.data[i] == ':') { return NGX_DECLINED; }
        }
        return NGX_OK;
    }
    if (hls_equal(origin, own)) { return NGX_OK; }
    if (c->origins) {
        allowed = c->origins->elts;
        for (i = 0; i < c->origins->nelts; i++) {
            if (hls_equal(origin, allowed[i])) { return NGX_OK; }
        }
    }
    return NGX_DECLINED;
}

static ngx_int_t
hls_unreserved(u_char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
        || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'
        || ch == '.' || ch == '~';
}

static ngx_int_t
hls_query(ngx_http_request_t *r, hls_conf_t *c, hls_ctx_t *ctx)
{
    hls_param_t *params;
    ngx_str_t *values;
    size_t size = 0, j;
    ngx_uint_t i;
    u_char *d, ch;
    static u_char hex[] = "0123456789ABCDEF";
    if (c->params == NULL) { return NGX_OK; }
    params = c->params->elts;
    values = ngx_pcalloc(r->pool, c->params->nelts * sizeof(ngx_str_t));
    if (values == NULL) { return NGX_ERROR; }
    for (i = 0; i < c->params->nelts; i++) {
        if (ngx_http_complex_value(r, &params[i].value, &values[i]) != NGX_OK) { return NGX_ERROR; }
        if (values[i].len == 0) { continue; }
        /* A query larger than a normal request line is almost certainly a misconfiguration. */
        if (values[i].len > c->line_size || size > c->line_size) { return NGX_ERROR; }
        size += params[i].name.len + values[i].len * 3 + 2;
    }
    if (size > c->line_size) { return NGX_ERROR; }
    ctx->query.data = ngx_pnalloc(r->pool, size + 1);
    if (ctx->query.data == NULL) { return NGX_ERROR; }
    d = ctx->query.data;
    for (i = 0; i < c->params->nelts; i++) {
        if (values[i].len == 0) { continue; }
        if (d != ctx->query.data) { *d++ = '&'; }
        d = ngx_cpymem(d, params[i].name.data, params[i].name.len); *d++ = '=';
        for (j = 0; j < values[i].len; j++) {
            ch = values[i].data[j];
            if (hls_unreserved(ch)) { *d++ = ch; }
            else { *d++ = '%'; *d++ = hex[ch >> 4]; *d++ = hex[ch & 15]; }
        }
    }
    ctx->query.len = d - ctx->query.data;
    return NGX_OK;
}

/* Compile named-variable interpolation without depending on nginx's changing
 * script-engine layout. Each value is snapshotted once before sizing/copying. */
static ngx_array_t *
hls_compile_sign(ngx_conf_t *cf, ngx_str_t text)
{
    ngx_array_t *parts;
    hls_sign_part_t *part;
    ngx_str_t name;
    size_t i = 0, start;
    ngx_flag_t braces;
    parts = ngx_array_create(cf->pool, 8, sizeof(hls_sign_part_t));
    if (parts == NULL) { return NULL; }
    while (i < text.len) {
        part = ngx_array_push(parts);
        if (part == NULL) { return NULL; }
        ngx_memzero(part, sizeof(*part)); part->index = NGX_ERROR;
        start = i;
        if (text.data[i] != '$') {
            while (i < text.len && text.data[i] != '$') { i++; }
            part->literal.data = text.data + start; part->literal.len = i - start;
            continue;
        }
        i++; braces = i < text.len && text.data[i] == '{';
        if (braces) { i++; }
        start = i;
        if (i < text.len && text.data[i] >= '0' && text.data[i] <= '9') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "secure_hls signing templates require named variables, not positional captures");
            return NULL;
        }
        while (i < text.len && ((text.data[i] >= 'a' && text.data[i] <= 'z')
               || (text.data[i] >= 'A' && text.data[i] <= 'Z')
               || (text.data[i] >= '0' && text.data[i] <= '9')
               || text.data[i] == '_')) { i++; }
        if (i == start || (braces && (i == text.len || text.data[i] != '}'))) { return NULL; }
        name.data = text.data + start; name.len = i - start;
        part->index = ngx_http_get_variable_index(cf, &name);
        if (part->index == NGX_ERROR) { return NULL; }
        if (braces) { i++; }
    }
    return parts;
}

static ngx_int_t
hls_sign_value(ngx_http_request_t *r, ngx_array_t *parts,
    ngx_pool_t *pool, size_t limit, ngx_str_t *result)
{
    hls_sign_part_t *p = parts->elts;
    ngx_str_t *values;
    ngx_http_variable_value_t *v;
    ngx_uint_t i, j;
    size_t size = 0;
    u_char *d;
    values = ngx_pcalloc(pool, parts->nelts * sizeof(ngx_str_t));
    if (values == NULL) { return NGX_ERROR; }
    for (i = 0; i < parts->nelts; i++) {
        if (p[i].index == NGX_ERROR) { values[i] = p[i].literal; }
        else {
            for (j = 0; j < i; j++) {
                if (p[j].index == p[i].index) { values[i] = values[j]; break; }
            }
            if (j == i) {
                v = ngx_http_get_flushed_variable(r, p[i].index);
                if (v == NULL) { return NGX_ERROR; }
                if (!v->not_found && v->len) {
                    if (v->len > limit - size) { return NGX_ERROR; }
                    values[i].data = ngx_pnalloc(pool, v->len);
                    if (values[i].data == NULL) { return NGX_ERROR; }
                    ngx_memcpy(values[i].data, v->data, v->len); values[i].len = v->len;
                }
            }
        }
        if (values[i].len > limit - size) { return NGX_ERROR; }
        size += values[i].len;
    }
    result->data = ngx_pnalloc(pool, size + 1);
    if (result->data == NULL) { return NGX_ERROR; }
    result->len = size;
    d = result->data;
    for (i = 0; i < parts->nelts; i++) {
        if (values[i].len) { d = ngx_cpymem(d, values[i].data, values[i].len); }
    }
    return NGX_OK;
}

static u_char *
hls_escape_value(u_char *d, ngx_str_t value)
{
    size_t i;
    u_char ch;
    static u_char hex[] = "0123456789ABCDEF";
    for (i = 0; i < value.len; i++) {
        ch = value.data[i];
        if (hls_unreserved(ch)) { *d++ = ch; }
        else { *d++ = '%'; *d++ = hex[ch >> 4]; *d++ = hex[ch & 15]; }
    }
    return d;
}

static ngx_int_t
hls_signed_query(ngx_http_request_t *r, hls_conf_t *c, hls_ctx_t *ctx,
    ngx_str_t raw_target, ngx_str_t *query)
{
    ngx_str_t origin, message, binary, token;
    ngx_array_t *parts;
    u_char digest[EVP_MAX_MD_SIZE], encoded[128], *d;
    unsigned int n;
    ngx_flag_t playlist;
    ngx_int_t rc;
    size_t size;
    ctx->target = raw_target;
    if (hls_resolve(r, c, ctx->scratch, r->uri, ctx->target,
                    &ctx->target_path, &origin) != NGX_OK) { return NGX_ERROR; }
    playlist = ctx->target_path.len >= 5
        && ngx_strncasecmp(ctx->target_path.data + ctx->target_path.len - 5,
                           (u_char *) ".m3u8", 5) == 0;
    parts = playlist ? c->sign_playlist_parts : c->sign_parts;
    ctx->target_active = 1;
    rc = hls_sign_value(r, parts, ctx->scratch, c->line_size * 4, &message);
    ctx->target_active = 0;
    if (rc != NGX_OK || ctx->bad_args) { return NGX_ERROR; }
    if (hls_digest(c->algorithm, ctx->signing_key, message, digest, &n) != NGX_OK) { return NGX_ERROR; }
    binary.data = digest; binary.len = n; token.data = encoded;
    if (c->encoding == 0) {
        ngx_hex_dump(encoded, digest, n); token.len = n * 2;
    } else if (c->encoding == 1) { ngx_encode_base64(&token, &binary); }
    else { ngx_encode_base64url(&token, &binary); }
    size = c->sign_param.len + 1 + token.len * 3;
    query->data = ngx_pnalloc(ctx->scratch, size + 1);
    if (query->data == NULL) { return NGX_ERROR; }
    d = ngx_cpymem(query->data, c->sign_param.data, c->sign_param.len); *d++ = '=';
    d = hls_escape_value(d, token);
    query->len = d - query->data;
    return NGX_OK;
}

static ngx_int_t
hls_uri(ngx_http_request_t *r, hls_conf_t *c, hls_ctx_t *ctx,
    ngx_str_t uri, ngx_str_t *out)
{
    size_t i;
    u_char *frag, *q, *end, *p, *amp, *eq, *d, *query_start;
    ngx_str_t raw, name, bare, generated = ngx_null_string;
    ngx_int_t rc, replace;
    hls_param_t *params;
    *out = uri;
    if (uri.len == 0) { return NGX_ERROR; }
    for (i = 0; i < uri.len; i++) {
        if (uri.data[i] <= 0x20 || uri.data[i] == 0x7f || uri.data[i] == '\\'
            || uri.data[i] == '"' || uri.data[i] == '<' || uri.data[i] == '>') { return NGX_ERROR; }
    }
    if (c->params == NULL && !c->resign) { return NGX_OK; }
    rc = hls_allowed(r, c, ctx->scratch, uri);
    if (rc == NGX_ERROR) { return NGX_ERROR; }
    if (rc == NGX_DECLINED) { return NGX_OK; }
    params = c->params ? c->params->elts : NULL;
    end = uri.data + uri.len;
    frag = ngx_strlchr(uri.data, end, '#'); if (frag == NULL) { frag = end; }
    q = ngx_strlchr(uri.data, frag, '?'); if (q == NULL) { q = frag; }
    bare.data = uri.data; bare.len = q - uri.data;
    if (c->resign && hls_signed_query(r, c, ctx, bare, &generated) != NGX_OK) { return NGX_ERROR; }
    out->data = ngx_pnalloc(ctx->scratch, uri.len + ctx->query.len + generated.len + 4);
    if (out->data == NULL) { return NGX_ERROR; }
    d = ngx_cpymem(out->data, uri.data, q - uri.data);
    query_start = d; *d++ = '?';
    p = q < frag ? q + 1 : frag;
    while (p < frag) {
        amp = ngx_strlchr(p, frag, '&'); if (amp == NULL) { amp = frag; }
        eq = ngx_strlchr(p, amp, '='); if (eq == NULL) { eq = amp; }
        raw.data = p; raw.len = eq - p;
        if (hls_decode(ctx->scratch, raw, &name) != NGX_OK) { return NGX_ERROR; }
        replace = 0;
        for (i = 0; c->params && i < c->params->nelts; i++) {
            if (hls_equal(name, params[i].name)) { replace = 1; break; }
        }
        if (c->resign && hls_equal(name, c->sign_param)) { replace = 1; }
        if (!replace && amp > p) {
            if (d > query_start + 1) { *d++ = '&'; }
            d = ngx_cpymem(d, p, amp - p);
        }
        p = amp < frag ? amp + 1 : frag;
    }
    if (ctx->query.len) {
        if (d > query_start + 1) { *d++ = '&'; }
        d = ngx_cpymem(d, ctx->query.data, ctx->query.len);
    }
    if (generated.len) {
        if (d > query_start + 1) { *d++ = '&'; }
        d = ngx_cpymem(d, generated.data, generated.len);
    }
    if (d == query_start + 1) { d = query_start; }
    d = ngx_cpymem(d, frag, end - frag);
    out->len = d - out->data;
    return NGX_OK;
}

static ngx_int_t
hls_line(ngx_http_request_t *r, hls_conf_t *c, hls_ctx_t *ctx, ngx_str_t *out)
{
    static struct { const char *name; ngx_uint_t mask; } tags[] = {
        { "#EXT-X-KEY:", HLS_KEYS }, { "#EXT-X-SESSION-KEY:", HLS_KEYS },
        { "#EXT-X-MAP:", HLS_MAPS }, { "#EXT-X-MEDIA:", HLS_MEDIA },
        { "#EXT-X-I-FRAME-STREAM-INF:", HLS_MEDIA }, { NULL, 0 }
    };
    ngx_str_t line, uri, result;
    size_t len, i, start = 0, finish = 0, attr, name_end, value;
    ngx_uint_t found = 0, quoted;
    u_char *d;
    line.data = ctx->line; line.len = ctx->len;
    *out = line;
    len = line.len;
    if (len && line.data[len - 1] == '\r') { len--; }
    if (!ctx->seen_magic) {
        if (len != 7 || ngx_memcmp(line.data, "#EXTM3U", 7) != 0) { return NGX_ERROR; }
        ctx->seen_magic = 1; return NGX_OK;
    }
    if (len == 0) { return NGX_OK; }
    if (line.data[0] != '#') {
        if (!(c->resources & HLS_LINES)) { return NGX_OK; }
        finish = len;
    } else {
        for (i = 0; tags[i].name; i++) {
            start = ngx_strlen(tags[i].name);
            if (len >= start && ngx_memcmp(line.data, tags[i].name, start) == 0) { break; }
        }
        if (tags[i].name == NULL || !(c->resources & tags[i].mask)) { return NGX_OK; }
        i = start;
        while (i < len) {
            while (i < len && (line.data[i] == ' ' || line.data[i] == '\t')) { i++; }
            attr = i;
            while (i < len && line.data[i] != '=' && line.data[i] != ',') { i++; }
            if (i == len || line.data[i] != '=') { return NGX_ERROR; }
            name_end = i;
            while (name_end > attr && line.data[name_end - 1] == ' ') { name_end--; }
            i++;
            while (i < len && line.data[i] == ' ') { i++; }
            quoted = i < len && line.data[i] == '"';
            if (quoted) { i++; }
            value = i;
            while (i < len && line.data[i] != (quoted ? '"' : ',')) { i++; }
            if (quoted && i == len) { return NGX_ERROR; }
            if (name_end - attr == 3 && ngx_memcmp(line.data + attr, "URI", 3) == 0) {
                if (!quoted || found || value == i) { return NGX_ERROR; }
                start = value; finish = i; found = 1;
            }
            if (quoted) { i++; }
            while (i < len && line.data[i] == ' ') { i++; }
            if (i < len) {
                if (line.data[i] != ',') { return NGX_ERROR; }
                i++;
            }
        }
        if (!found) { return NGX_OK; }
    }
    uri.data = line.data + start; uri.len = finish - start;
    if (hls_uri(r, c, ctx, uri, &result) != NGX_OK) { return NGX_ERROR; }
    out->len = line.len - uri.len + result.len;
    out->data = ngx_pnalloc(ctx->scratch, out->len + 1);
    if (out->data == NULL) { return NGX_ERROR; }
    d = ngx_cpymem(out->data, line.data, start);
    d = ngx_cpymem(d, result.data, result.len);
    ngx_memcpy(d, line.data + finish, line.len - finish);
    return NGX_OK;
}

static void
hls_pool_cleanup(void *data)
{
    ngx_destroy_pool(data);
}

static ngx_int_t
hls_playlist_type(ngx_http_request_t *r, hls_conf_t *c)
{
    ngx_str_t t = r->headers_out.content_type, *types;
    ngx_uint_t i;
    u_char *semi;
    if (t.len == 0) { return 0; }
    semi = ngx_strlchr(t.data, t.data + t.len, ';');
    if (semi) { t.len = semi - t.data; }
    while (t.len && t.data[t.len - 1] == ' ') { t.len--; }
    if (c->types) {
        types = c->types->elts;
        for (i = 0; i < c->types->nelts; i++) {
            if (t.len == types[i].len && ngx_strncasecmp(t.data, types[i].data, t.len) == 0) { return 1; }
        }
        return 0;
    }
    return (t.len == 29 && ngx_strncasecmp(t.data, (u_char *) "application/vnd.apple.mpegurl", 29) == 0)
        || (t.len == 21 && ngx_strncasecmp(t.data, (u_char *) "application/x-mpegurl", 21) == 0);
}

static ngx_int_t
hls_header(ngx_http_request_t *r)
{
    hls_conf_t *c = ngx_http_get_module_loc_conf(r, ngx_http_secure_hls_module);
    hls_ctx_t *ctx;
    ngx_pool_cleanup_t *cleanup;
    ngx_list_part_t *part;
    ngx_table_elt_t *h, *cc;
    ngx_uint_t i;
    if (!c->rewrite || r != r->main
        || (!hls_playlist_path(r) && !hls_playlist_type(r, c))) { return hls_next_header(r); }
    if (r->headers_out.status != NGX_HTTP_OK && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
        && r->headers_out.status != NGX_HTTP_NOT_MODIFIED) { return hls_next_header(r); }
    ctx = hls_context(r); if (ctx == NULL) { return NGX_ERROR; }
    if (r->headers_out.status != NGX_HTTP_OK
        || (r->headers_out.content_encoding && r->headers_out.content_encoding->value.len))
    {
        hls_fail(ctx, "unsupported_response", 0);
        return ngx_http_filter_finalize_request(r, &ngx_http_secure_hls_module, NGX_HTTP_BAD_GATEWAY);
    }
    if (hls_parse_args(r, ctx) != NGX_OK || hls_query(r, c, ctx) != NGX_OK) {
        return ngx_http_filter_finalize_request(r, &ngx_http_secure_hls_module, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    if (ctx->bad_args) {
        return ngx_http_filter_finalize_request(r, &ngx_http_secure_hls_module, NGX_HTTP_FORBIDDEN);
    }
    if (c->resign && c->algorithm == 2
        && ngx_http_complex_value(r, c->key, &ctx->signing_key) != NGX_OK)
    {
        return ngx_http_filter_finalize_request(r, &ngx_http_secure_hls_module, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    ngx_http_clear_content_length(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_etag(r);
    ngx_http_clear_accept_ranges(r);
    r->allow_ranges = 0;
    part = &r->headers_out.headers.part;
    for (i = 0, h = part->elts; ; i++) {
        if (i == part->nelts) {
            if (part->next == NULL) { break; }
            part = part->next; h = part->elts; i = 0;
        }
        if ((h[i].key.len == 13 && ngx_strncasecmp(h[i].key.data, (u_char *) "Cache-Control", 13) == 0)
            || (h[i].key.len == 7 && ngx_strncasecmp(h[i].key.data, (u_char *) "Expires", 7) == 0))
        { h[i].hash = 0; }
    }
    r->headers_out.expires = NULL;
    cc = ngx_list_push(&r->headers_out.headers);
    if (cc == NULL) { return NGX_ERROR; }
    ngx_memzero(cc, sizeof(*cc));
    cc->hash = 1; ngx_str_set(&cc->key, "Cache-Control");
    ngx_str_set(&cc->value, "private, no-store");
    r->headers_out.cache_control = cc;
    if (!r->header_only) {
        ctx->line = ngx_pnalloc(r->pool, c->line_size);
        if (ctx->line == NULL) { return NGX_ERROR; }
        cleanup = ngx_pool_cleanup_add(r->pool, 0);
        if (cleanup == NULL) { return NGX_ERROR; }
        ctx->scratch = ngx_create_pool(4096, r->connection->log);
        if (ctx->scratch == NULL) { return NGX_ERROR; }
        cleanup->data = ctx->scratch; cleanup->handler = hls_pool_cleanup;
        ctx->active = 1;
        r->filter_need_in_memory = 1;
    }
    return hls_next_header(r);
}

static ngx_int_t
hls_send(ngx_http_request_t *r, hls_ctx_t *ctx, ngx_str_t data,
    ngx_flag_t newline, ngx_flag_t last, ngx_flag_t flush)
{
    ngx_chain_t *out, *cl;
    ngx_buf_t *b;
    u_char *start, *end;
    ngx_int_t rc;
    hls_conf_t *c = ngx_http_get_module_loc_conf(r, ngx_http_secure_hls_module);
    size_t capacity = c->line_size + ctx->query.len + 4;
    if (c->resign) {
        capacity += 512 + c->sign_param.len;
    }
    out = ctx->pending;
    if (out == NULL || data.len + newline > (size_t) (out->buf->end - out->buf->last)) {
        cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (cl == NULL) { return NGX_ERROR; }
        b = cl->buf; start = b->start; end = b->end;
        if (start == NULL) {
            start = ngx_pnalloc(r->pool, capacity);
            if (start == NULL) { return NGX_ERROR; }
            end = start + capacity;
        }
        ngx_memzero(b, sizeof(*b));
        b->start = start; b->end = end; b->pos = start; b->last = start;
        b->tag = (ngx_buf_tag_t) &ngx_http_secure_hls_module;
        cl->next = NULL;
        if (out) { out->next = cl; } else { out = cl; }
    } else {
        cl = out; b = cl->buf;
    }
    if (data.len + newline > (size_t) (b->end - b->last)) { return NGX_ERROR; }
    if (data.len) { b->last = ngx_cpymem(b->last, data.data, data.len); }
    if (newline) { *b->last++ = '\n'; }
    b->temporary = b->last > b->pos;
    if (!last && !flush && out->next == NULL && (b->last - b->pos) < 16384) {
        ctx->pending = out;
        return NGX_OK;
    }
    b->last_buf = last; b->last_in_chain = last; b->flush = !last;
    ctx->pending = NULL;
    rc = hls_next_body(r, out);
    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                           (ngx_buf_tag_t) &ngx_http_secure_hls_module);
    return rc;
}

static ngx_int_t
hls_body(ngx_http_request_t *r, ngx_chain_t *in)
{
    hls_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_secure_hls_module);
    hls_conf_t *c;
    ngx_buf_t *b;
    ngx_chain_t *cl, *out = NULL;
    ngx_str_t line, empty = ngx_null_string;
    ngx_int_t rc;
    u_char *lf;
    size_t n;
    ngx_flag_t last, flush;
    if (ctx == NULL || !ctx->active) { return hls_next_body(r, in); }
    c = ngx_http_get_module_loc_conf(r, ngx_http_secure_hls_module);
    if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) { return NGX_ERROR; }
    for ( ;; ) {
        if (ctx->busy) {
            rc = hls_next_body(r, NULL);
            if (rc == NGX_ERROR) { return rc; }
            ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                                   (ngx_buf_tag_t) &ngx_http_secure_hls_module);
            if (ctx->busy) { r->buffered |= HLS_BUFFERED; return NGX_AGAIN; }
        }
        if (ctx->in == NULL) { break; }
        b = ctx->in->buf;
        if (ngx_buf_size(b)) {
            if (ctx->finished || !ngx_buf_in_memory(b)) { goto malformed; }
            lf = ngx_strlchr(b->pos, b->last, '\n');
            n = (lf ? lf : b->last) - b->pos;
            if (n > c->line_size - ctx->len) { goto malformed; }
            ngx_memcpy(ctx->line + ctx->len, b->pos, n); ctx->len += n;
            b->pos += n;
            if (b->in_file) { b->file_pos += n; }
            if (lf == NULL) { continue; }
            b->pos++;
            if (b->in_file) { b->file_pos++; }
            ngx_reset_pool(ctx->scratch);
            if (hls_line(r, c, ctx, &line) != NGX_OK) { goto malformed; }
            rc = hls_send(r, ctx, line, 1, 0, 0);
            ctx->len = 0;
            if (rc == NGX_ERROR) { return rc; }
            continue;
        }
        last = b->last_buf;
        flush = b->flush;
        if (last && ctx->len) {
            ngx_reset_pool(ctx->scratch);
            if (hls_line(r, c, ctx, &line) != NGX_OK) { goto malformed; }
            rc = hls_send(r, ctx, line, 0, 0, 0);
            ctx->len = 0;
            if (rc == NGX_ERROR) { return rc; }
            continue;
        }
        cl = ctx->in; ctx->in = cl->next; ngx_free_chain(r->pool, cl);
        if (last) {
            if (!ctx->seen_magic || ctx->finished) { goto malformed; }
            ctx->finished = 1;
        }
        if (last || flush) {
            rc = hls_send(r, ctx, empty, 0, last, flush);
            if (rc == NGX_ERROR) { return rc; }
        }
    }
    if (ctx->len || ctx->busy || ctx->in || ctx->pending) { r->buffered |= HLS_BUFFERED; }
    else { r->buffered &= ~HLS_BUFFERED; }
    return NGX_OK;
malformed:
    hls_fail(ctx, "invalid_playlist", 0);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "secure_hls: invalid playlist, oversized line or invalid buffer");
    return NGX_ERROR;
}

static ngx_int_t
hls_target_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    hls_ctx_t *ctx = hls_context(r);
    ngx_str_t value;
    if (ctx == NULL) { return NGX_ERROR; }
    v->no_cacheable = 1;
    if (!ctx->target_active && data != 3) { v->not_found = 1; return NGX_OK; }
    value = data == 0 ? ctx->target : data == 3 ? r->uri : ctx->target_path;
    if (data >= 2) {
        size_t i;
        for (i = value.len; i > 0; i--) {
            if (value.data[i - 1] == '/') {
                value.data += i; value.len -= i; break;
            }
        }
    }
    v->data = value.data; v->len = value.len; v->valid = 1; v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
hls_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *v;
    ngx_uint_t i;
    ngx_str_t targets[] = { ngx_string("secure_hls_target"),
        ngx_string("secure_hls_target_path"), ngx_string("secure_hls_target_filename"),
        ngx_string("secure_hls_filename") };
    ngx_str_t arg = ngx_string("secure_hls_arg_");
    ngx_str_t status = ngx_string("secure_hls_status");
    v = ngx_http_add_variable(cf, &arg, NGX_HTTP_VAR_PREFIX|NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) { return NGX_ERROR; }
    v->get_handler = hls_arg_variable;
    v = ngx_http_add_variable(cf, &status, NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) { return NGX_ERROR; }
    v->get_handler = hls_status_variable;
    for (i = 0; i < 4; i++) {
        v = ngx_http_add_variable(cf, &targets[i], NGX_HTTP_VAR_NOCACHEABLE);
        if (v == NULL) { return NGX_ERROR; }
        v->get_handler = hls_target_variable; v->data = i;
    }
    return NGX_OK;
}

static ngx_int_t
hls_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) { return NGX_ERROR; }
    /* Phase handlers run in reverse registration order. Run after RealIP's
     * location-level handler, even when this module was loaded dynamically. */
    h = cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers.elts;
    ngx_memmove(h + 1, h,
        (cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers.nelts - 1) * sizeof(*h));
    h[0] = hls_access;
    hls_next_header = ngx_http_top_header_filter;
    ngx_http_top_header_filter = hls_header;
    hls_next_body = ngx_http_top_body_filter;
    ngx_http_top_body_filter = hls_body;
    return NGX_OK;
}
