
/*
 * Copyright (C) Jikui Pei
 */

#ifndef _NGX_STREAM_SSL_H_INCLUDED_
#define _NGX_STREAM_SSL_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <nginx.h>


#define NGX_STREAM_ALG_DOWNSTREAM 0
#define NGX_STREAM_ALG_UPSTREAM 1

typedef ngx_int_t (*ngx_stream_alg_handler_pt)(ngx_stream_session_t *s,u_char *buf,ssize_t ssize);
typedef ngx_int_t (*ngx_stream_alg_process_handler_pt)(ngx_stream_session_t *s);
typedef void (*ngx_stream_ream_handler)(ngx_event_t *ev);
typedef ngx_event_handler_pt (*ngx_stream_alg_get_handler)(ngx_stream_session_t *s, ngx_event_handler_pt handler,ngx_int_t up_down);


typedef struct {
    ngx_flag_t       alg_ftp;
} ngx_stream_alg_srv_conf_t;

typedef struct {
    ngx_stream_alg_handler_pt      alg_handler;

    ngx_event_handler_pt  alg_downstream_handler;
    ngx_event_handler_pt  alg_upstream_handler;
    ngx_event_handler_pt  previous_upstream_handler;
    ngx_event_handler_pt previous_downstream_handler;
    ngx_stream_alg_get_handler alg_get_stream_handler;

}ngx_stream_alg_main_conf_t;

typedef struct {
    ngx_stream_upstream_resolved_t *alg_resolved_peer;
} ngx_stream_alg_ctx_t;

extern ngx_module_t ngx_stream_alg_module;
#endif
