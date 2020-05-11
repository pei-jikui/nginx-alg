
/*
 * Copyright (C) Jikui Pei
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <nginx.h>
#include <ngx_stream_alg_module.h>

static ngx_int_t ngx_stream_alg_init(ngx_conf_t *cf);
static ngx_int_t ngx_stream_alg_handler(ngx_stream_session_t *s);
static char * ngx_stream_alg_alg(ngx_conf_t *cf, ngx_command_t *cmd, 
                                 void *conf);
static ngx_event_handler_pt ngx_stream_alg_get_stream_handler(
                                ngx_stream_session_t *s,
                                ngx_event_handler_pt handler, 
                                ngx_int_t up_down);
static void * ngx_stream_alg_create_srv_conf(ngx_conf_t *cf);
static void * ngx_stream_alg_create_main_conf(ngx_conf_t *cf);

static ngx_command_t  ngx_stream_alg_commands[] = {

    { ngx_string("alg"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_alg_alg,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL 
    },
      
    ngx_null_command
};


static ngx_stream_module_t  ngx_stream_alg_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_alg_init,           /* postconfiguration */

    ngx_stream_alg_create_main_conf,      /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_alg_create_srv_conf,       /* create server configuration */
    NULL,
};


ngx_module_t  ngx_stream_alg_module = {
    NGX_MODULE_V1,
    &ngx_stream_alg_module_ctx,           /* module context */
    ngx_stream_alg_commands,              /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t 
ngx_stream_alg_ftp_get_peer_addr(ngx_stream_session_t *s, u_char *addr_info, 
        ssize_t size)
{
    ngx_stream_alg_ctx_t       *ctx;
    ngx_stream_upstream_resolved_t *peer = NULL;
    unsigned int addr1,addr2,addr3,addr4;
    unsigned int port1,port2;
    u_char server_addr[INET_ADDRSTRLEN+1] = {0};
    struct sockaddr_in   *sin;
    ngx_connection_t *c;

    c = s->connection;
    
    if ( ngx_strlchr(addr_info,addr_info+size-1,',') == NULL) {
        return NGX_ERROR;
    }
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_alg_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    
    peer = ctx->alg_resolved_peer;
    if (peer == NULL || peer->sockaddr == NULL) {
        return NGX_ERROR;
    }

    if (sscanf((const char*)addr_info,"%u,%u,%u,%u,%u,%u",&addr1,&addr2,&addr3,
               &addr4,&port1,&port2) != 6){
        return NGX_ERROR;
    }
    
    ngx_snprintf(server_addr,INET_ADDRSTRLEN,"%ud.%ud.%ud.%ud",addr1,addr2,
                 addr3,addr4);
    
    sin = (struct sockaddr_in *)peer->sockaddr;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port1*256+port2);
    sin->sin_addr.s_addr = ngx_inet_addr(server_addr,ngx_strlen(server_addr));
    if (sin->sin_addr.s_addr == INADDR_NONE) {
        return NGX_ERROR;
    }
    peer->socklen = sizeof(struct sockaddr_in);
    peer->naddrs = 1;
    peer->port =htons(port1*256+port2);
    peer->no_port = 0;
    return NGX_OK;
}

static ngx_int_t ngx_stream_alg_create_listening_port(ngx_stream_session_t *s)
{
    u_char * p;
    struct sockaddr_in          *sin;
    struct sockaddr_in sockaddr;
    ngx_listening_t             *ls;
    ngx_listening_t             *ls_ctl;
    ngx_uint_t  port_num = 0;
    socklen_t socklen = sizeof(struct sockaddr_in);
    

    ls_ctl = s->connection->listening;
    if (ls_ctl == NULL) {
        return NGX_ERROR;
    }
    p = ngx_pcalloc(s->connection->pool, sizeof(struct sockaddr_in));
    if (p == NULL) {
        return NGX_ERROR;
    }
    sin = (struct sockaddr_in *) p;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(0);
    sin->sin_addr.s_addr = INADDR_ANY;
    ls = ngx_pcalloc(s->connection->pool,sizeof(ngx_listening_t));
    *ls =  *ls_ctl;
    ls->ignore = 0;
    ls->fd = -1;
    ls->inherited = 0;
    ls->reuseport = 0;
    ls->sockaddr = (struct sockaddr *)p;
    ls->parent_stream_session = s ;
    ls->worker = ngx_worker;
    ls->addr_text.len = INET_ADDRSTRLEN+1+8;
    ls->addr_text.data = ngx_pcalloc(s->connection->pool,ls->addr_text.len);
    ngx_memset(ls->addr_text.data,0,ls->addr_text.len);
    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
             "original listening socket work id %ud : current work id %ud",
             ls->worker,ngx_worker);
    if (ngx_open_one_listening_socket(ls) == NGX_ERROR) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                "Failed to create listening socket on port number.");
        return NGX_ERROR;
    }

    if ( ngx_event_one_listening_init(ls) == NGX_ERROR) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "Failed to initialize listening socket on port number: \
                       %ud", port_num);
        return NGX_ERROR;
    
    }
    if (getsockname(ls->fd, (struct sockaddr *)&sockaddr,&socklen) == -1) {
        return NGX_ERROR;
    }

    port_num = ntohs(sockaddr.sin_port);
    ngx_snprintf(ls->addr_text.data,ls->addr_text.len,"0.0.0.0:%ud",port_num);
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "Create listening port number %ud.",port_num);
    return port_num;
}

/*Three kinds of return values*/
/*
 *1. NGX_ERROR exception
 *2. NGX_OK processed. 
 *3. NGX_CONTINUE which means more data is required
 */
static ngx_int_t 
ngx_stream_alg_ftp_process_handler(ngx_stream_session_t *s,ngx_buf_t* buffer)
{
    u_char * command = NULL;
    u_char pasv[] = "227 Entering Passive Mode (";
    u_char port[] = "PORT ";
    u_char *left_brace = NULL;
    u_char *right_brace = NULL;
    struct sockaddr_in sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    ngx_socket_t fd = s->connection->fd;
    u_char addr_str[INET_ADDRSTRLEN+1] = {0};
    unsigned int addr1,addr2,addr3,addr4;
    unsigned int entering_alg = 0;
    ngx_connection_t *c;

    ngx_uint_t total_len = 0;
    ngx_int_t number;
    
    c = s->connection;

    total_len = buffer->last - buffer->pos;
    
    if (total_len < 2) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                "%s size is too short to find the CRLF.",__func__);
        return NGX_AGAIN;   
    }
    command = buffer->pos;

    /*check the buf ends with the \r\n */

    if (ngx_strstrn(command+total_len-2,CRLF,2) == NULL ) {

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                "%s Don't find a full sentence %s with \"\\r\\n\"",
                __func__,command);
        return NGX_AGAIN;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
            "%s find a full sentence %s with \"\\r\\n\"",__func__,command);
    if (ngx_strstr(command,pasv) != NULL) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                "%s:Entering Passive Mode.%s",__func__,command);

        left_brace = ngx_strlchr(command,command + total_len -1,'(');
        right_brace = ngx_strlchr(command,command +total_len -1,')');
        if (left_brace == NULL || right_brace == NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                    "%s:Couldn't find the right pattern string.",__func__);
            return NGX_OK;
        }
        entering_alg = 1;

    } else if (ngx_strstr(command,port) != NULL) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                "%s:Entering Port Mode.%s",__func__,command);
        left_brace = ngx_strlchr(command,command +  total_len -1,' ');
        right_brace = ngx_strlchr(command,command +total_len -1,'\r');
        if (left_brace == NULL || right_brace == NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                    "%s:Couldn't find the right pattern string.",__func__);
            return NGX_OK;
        }
        entering_alg = 2;
    }

    if (entering_alg > 0) {
        ngx_int_t port_num = 0;
        ngx_uint_t try_times = 0;
        left_brace += 1;
        right_brace -= 1;
        if (ngx_stream_alg_ftp_get_peer_addr(s,left_brace,
                                            right_brace-left_brace+1) < 0){
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                    "%s:Doesn't contain the right pattern for ip and port.",
                    __func__);
            return NGX_OK;
        }
        if (entering_alg == 1) {
            if (getsockname(fd, (struct sockaddr *)&sockaddr,&socklen) == -1) {
                return NGX_ERROR;
            }
            ngx_inet_ntop(sockaddr.sin_family,
                          (struct sockaddr *)&sockaddr.sin_addr, addr_str,
                          INET_ADDRSTRLEN);
            ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                    "%s the address is %s.",__func__,addr_str);
            number = sscanf((const char *)addr_str,"%u.%u.%u.%u",&addr1,
                            &addr2,&addr3,&addr4);
        }else {
            fd = s->upstream ->peer.connection->fd;
            if (getsockname(fd, (struct sockaddr *)&sockaddr,&socklen) == -1) {
                return NGX_ERROR;
            }
            ngx_inet_ntop(sockaddr.sin_family,
                          (struct sockaddr *)&sockaddr.sin_addr, 
                          addr_str,INET_ADDRSTRLEN);
            ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                    "%s the address is %s.",__func__,addr_str);
            number = sscanf((const char *)addr_str,"%u.%u.%u.%u",&addr1,&addr2,
                            &addr3,&addr4);

        }
        if(number != 4 ) {
            return NGX_OK;
        }
        while (port_num <=0 && try_times++ < 5) {
            port_num = ngx_stream_alg_create_listening_port(s);
        }
        if (try_times >= 5 ) {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                    "%s allocate a new socket for data session failed.",
                    __func__);
            return NGX_ERROR;
        }
        ngx_memset(buffer->pos,0,total_len);
        if (entering_alg == 1) {
            ngx_snprintf(buffer->pos,80,"227 Entering Passive Mode \
                    (%ud,%ud,%ud,%ud,%ud,%ud).\r\n",
                    addr1,addr2,addr3,addr4,port_num/256,port_num%256);
        }else {
            ngx_snprintf(buffer->pos,80,"PORT %ud,%ud,%ud,%ud,%ud,%ud\r\n",
                    addr1,addr2,addr3,addr4,port_num/256,port_num%256);
        }
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                "%s new buffer is %s.",__func__,buffer->pos);
        
        buffer->last = buffer->pos + ngx_strlen(buffer->pos);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_alg_handler(ngx_stream_session_t *s)
{
    ngx_stream_alg_srv_conf_t  *ascf;
    ngx_connection_t *c;
    ngx_stream_alg_ctx_t       *ctx;
    ngx_listening_t             *ls;

    ascf = ngx_stream_get_module_srv_conf(s,ngx_stream_alg_module);
    if (ascf->alg_ftp != 1 ) {
        return NGX_DECLINED;
    }
    c = s->connection;
    
    if ( c->type != SOCK_STREAM ) {
        return NGX_DECLINED;
    }
    
    ls = c->listening;
    
    /*Only create the context for parent sessions*/
    if (ls->parent_stream_session == NULL ) {
        ctx = ngx_stream_get_module_ctx(s, ngx_stream_alg_module);
        if (ctx == NULL) {
            ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_alg_ctx_t));
            if (ctx == NULL) {
                return NGX_ERROR;
            }
            ngx_stream_set_ctx(s, ctx, ngx_stream_alg_module);
            ctx->alg_resolved_peer = ngx_pcalloc(c->pool,sizeof(ngx_stream_upstream_resolved_t));
            if (ctx->alg_resolved_peer == NULL){
                return NGX_ERROR;
            }
            ctx->alg_resolved_peer->sockaddr = ngx_pcalloc(c->pool,sizeof(struct sockaddr_in));
            if (ctx->alg_resolved_peer->sockaddr == NULL){
                return NGX_ERROR;
            }

        }
    }

    if ( c->buffer == NULL ) {
        return NGX_DECLINED;
    }
    
    return NGX_AGAIN;
}


char *
ngx_stream_alg_alg(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

    ngx_stream_alg_srv_conf_t *ascf = conf;
    ngx_str_t                       *value;
    value = cf->args->elts;
    if (ngx_strcmp(value[1].data,"ftp") == 0) {
        ascf->alg_ftp = 1;
    } else {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
static void *
ngx_stream_alg_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_alg_main_conf_t *amcf;
    amcf = ngx_pcalloc(cf->pool,sizeof(ngx_stream_alg_main_conf_t));
    if (amcf == NULL) {
        return NULL;
    }
    amcf->alg_get_stream_handler = ngx_stream_alg_get_stream_handler;
    return amcf;
}
static void *
ngx_stream_alg_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_alg_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_alg_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static ngx_int_t
ngx_stream_alg_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_alg_handler;

    return NGX_OK;
}

static ngx_int_t ngx_stream_stream_handler(ngx_event_t *ev, 
        ngx_int_t stream_direction)
{
    ngx_connection_t             *c;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    size_t                       size;
    ssize_t                      n;
    ngx_chain_t                  *cl;
    ngx_int_t                    rc;
    ngx_stream_core_srv_conf_t  *cscf;
    
    c = ev->data;
    s = c->data;
    u = s->upstream;
    
    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
    if (cscf == NULL) {
        rc = NGX_ERROR;
        return rc;
    }

    if (c->read->timedout) {
    } else if (c->read->timer_set) {
    } else {
    }
    
    if (c->buffer == NULL) {
        c->buffer = ngx_create_temp_buf(c->pool, cscf->preread_buffer_size);
        if (c->buffer == NULL) {
            rc = NGX_ERROR;
            return rc;
        }
    }

    size = c->buffer->end - c->buffer->last;

    if (size == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "preread buffer full");
        rc = NGX_ERROR;
        return rc;
    }

    if (c->read->eof) {
        rc = NGX_OK;
        return rc;
    }

    if (!c->read->ready) {
        rc = NGX_OK;
        return rc;
    }
    
    n = c->recv(c, c->buffer->last, size);
    
    /*Error happened*/
    if (n == NGX_ERROR || n == 0) {
        rc = NGX_STREAM_OK;
        if (ngx_handle_read_event(c->read, NGX_CLOSE_EVENT) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    if (n == NGX_AGAIN) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
            "%s content is : %s",
            __func__,c->buffer->pos);

    c->buffer->last += n;
    rc = ngx_stream_alg_ftp_process_handler(s,c->buffer);
    
    if (rc == NGX_ERROR) {
        return rc;
    } else {
        if (rc == NGX_AGAIN) {
            return rc;
        }       
    }
    
     /*merge the read buffer*/
    if (c->buffer && c->buffer->pos < c->buffer->last) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add preread size: %uz buffer:%s",
                       c->buffer->last - c->buffer->pos,c->buffer->pos);

        cl = ngx_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                    "couldn't get the free buf: %s", __func__);
            rc = NGX_ERROR;
            return rc;
        }

        *cl->buf = *c->buffer;

        cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_alg_module;
        cl->buf->flush = 1;
        if (stream_direction == NGX_STREAM_ALG_UPSTREAM) {
            cl->next = u->downstream_out;
            u->downstream_out = cl;
        } else {
            cl->next = u->upstream_out;
            u->upstream_out = cl;
        }
    }
    c->buffer->pos = c->buffer->last;
    return NGX_OK;
}
static void ngx_stream_alg_stream_handler(ngx_event_t *ev, 
        ngx_int_t stream_direction)
{
    ngx_stream_alg_main_conf_t *amcf;
    ngx_int_t rc;
    ngx_connection_t             *c;
    ngx_stream_session_t         *s;
    
    c = ev->data;
    s = c->data;

    amcf = ngx_stream_get_module_main_conf(s,ngx_stream_alg_module);
    if (amcf == NULL) {
        return;
    }

    rc = ngx_stream_stream_handler(ev,stream_direction);
    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                "stream handler error: %s", __func__);
        return;
    }
    if (stream_direction == NGX_STREAM_ALG_UPSTREAM) {
        (amcf->previous_upstream_handler)(ev);
    } else {
        (amcf->previous_downstream_handler)(ev);
    }
    return;
}
static void ngx_stream_alg_upstream_handler(ngx_event_t *ev)
{
    ngx_stream_alg_stream_handler(ev,NGX_STREAM_ALG_UPSTREAM);
    return;
}
static void ngx_stream_alg_downstream_handler(ngx_event_t *ev)
{
    ngx_stream_alg_stream_handler(ev,NGX_STREAM_ALG_DOWNSTREAM);
    return;
}

static ngx_event_handler_pt ngx_stream_alg_get_stream_handler(
        ngx_stream_session_t *s,
        ngx_event_handler_pt pre_handler, 
        ngx_int_t up_down)
{
    ngx_event_handler_pt handler = NULL;
    ngx_stream_alg_main_conf_t *amcf;
    
    amcf = ngx_stream_get_module_main_conf(s,ngx_stream_alg_module);
    if (amcf == NULL) {
        return handler;
    }
    /*downstream*/
    if (up_down == NGX_STREAM_ALG_DOWNSTREAM) {
        amcf->previous_downstream_handler = pre_handler;
        handler = ngx_stream_alg_downstream_handler;
    } else {
        amcf->previous_upstream_handler = pre_handler;
        handler =  ngx_stream_alg_upstream_handler;
    }   
    return handler;
}
