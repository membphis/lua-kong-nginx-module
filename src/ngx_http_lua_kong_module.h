#ifndef _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_
#define _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_LUA_KONG_SSL_VERIFY_ON    0x1
#define NGX_HTTP_LUA_KONG_SSL_VERIFY_OFF   0x2


typedef struct {
    STACK_OF(X509)      *upstream_client_certificate_chain;
    EVP_PKEY            *upstream_client_private_key;
    X509_STORE          *upstream_trusted_store;
    int                 upstream_ssl_verify;
    int                 upstream_ssl_verify_depth;
} ngx_http_lua_kong_ctx_t;


void ngx_http_lua_kong_set_upstream_ssl(ngx_http_request_t *r,
    ngx_connection_t *c);

ngx_uint_t
ngx_http_lua_kong_get_upstream_ssl_verify(ngx_http_request_t *r, int proxy_ssl_verify);


#endif /* _NGX_HTTP_LUA_KONG_MODULE_H_INCLUDED_ */
