
/*
 * Copyright (C) Jikui Pei
 */

#ifndef _NGX_STREAM_SSL_H_INCLUDED_
#define _NGX_STREAM_SSL_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <nginx.h>

typedef struct {
    ngx_flag_t       alg_ftp;
} ngx_stream_alg_srv_conf_t;

typedef struct {
    ngx_stream_upstream_resolved_t *alg_resolved_peer;
    ngx_stream_alg_handler_pt      alg_handler;
} ngx_stream_alg_ctx_t;

extern ngx_module_t ngx_stream_alg_module;
#endif
