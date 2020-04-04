
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
static char * ngx_stream_alg_alg(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void * ngx_stream_alg_create_srv_conf(ngx_conf_t *cf);

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

    NULL,                                  /* create main configuration */
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


static ngx_int_t 
ngx_stream_alg_ftp_get_peer_addr(ngx_stream_session_t *s, u_char *addr_info, ssize_t size)
{
    ngx_stream_alg_ctx_t       *ctx;
    ngx_stream_upstream_resolved_t *peer = NULL;
    unsigned int addr1,addr2,addr3,addr4;
    unsigned int port1,port2;
    u_char* server_addr = NULL;
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
    
    if (sscanf((const char*)addr_info,"%u,%u,%u,%u,%u,%u",&addr1,&addr2,&addr3,&addr4,&port1,&port2) != 6){
        return NGX_ERROR;
    }
    
    server_addr = ngx_pcalloc(c->pool,INET_ADDRSTRLEN+1);
    if (server_addr == NULL ){
        return NGX_ERROR;
    }
    ngx_snprintf(server_addr,INET_ADDRSTRLEN,"%ud.%ud.%ud.%ud",addr1,addr2,addr3,addr4);
    
    peer = ngx_pcalloc(c->pool,sizeof(ngx_stream_upstream_resolved_t));
    if (peer == NULL) {
        ngx_pfree(c->pool,server_addr);
        return NGX_ERROR;
    }

    peer->sockaddr = ngx_pcalloc(c->pool,sizeof(struct sockaddr_in));
    if (peer->sockaddr == NULL) {
        ngx_pfree(c->pool,server_addr);
        ngx_pfree(c->pool,peer);
        return NGX_ERROR;
    }

    sin = (struct sockaddr_in *)peer->sockaddr;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port1*256+port2);
    sin->sin_addr.s_addr = ngx_inet_addr(server_addr,ngx_strlen(server_addr));
    if (sin->sin_addr.s_addr == INADDR_NONE) {
        ngx_pfree(c->pool,server_addr);
        ngx_pfree(c->pool,peer);
        return NGX_ERROR;
    }
    peer->socklen = sizeof(struct sockaddr_in);
    peer->naddrs = 1;
    peer->port =htons(port1*256+port2);
    peer->no_port = 0;
    ngx_pfree(c->pool,server_addr);
    ctx->alg_resolved_peer = peer;
    return NGX_OK;
}

static ngx_int_t ngx_stream_alg_create_listening_port(ngx_stream_session_t *s)
{
    static int times = 0;
    u_char * p;
    struct sockaddr_in          *sin;
    ngx_listening_t             *ls;
    ngx_listening_t             *ls_ctl;
    ngx_int_t  port_num = 2180 + times;
    times ++;
    times %= 50;
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "create listening socket on port number: %ud",port_num);

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
    sin->sin_port = htons(port_num);
    sin->sin_addr.s_addr = INADDR_ANY;
    ls = ngx_pcalloc(s->connection->pool,sizeof(ngx_listening_t));
    *ls =  *ls_ctl;
    ls->ignore = 0;
    ls->fd = -1;
    ls->inherited = 0;
    ls->reuseport = 1;
    ls->sockaddr = (struct sockaddr *)p;
    ls->parent_stream_session = s ;
    if (ngx_open_one_listening_socket(ls) == NGX_ERROR) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                "Failed to create listening socket on port number: %ud",port_num);
        ngx_pfree(s->connection->pool,ls);
        ngx_pfree(s->connection->pool,p);
        return NGX_ERROR;
    }
    ngx_event_one_listening_init(ls);
    return port_num;
}

static ngx_int_t 
ngx_stream_alg_ftp_process(ngx_stream_session_t *s,u_char* buf,ssize_t size)
{
    u_char * command = NULL;
    u_char * new_buf = NULL;
    u_char pasv[] = "227 Entering Passive Mode (";
    u_char port[] = "PORT ";
    u_char *left_brace = NULL;
    u_char *right_brace = NULL;
    struct sockaddr_in sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    ngx_socket_t fd = s->connection->fd;
    u_char addr_str[INET_ADDRSTRLEN+1] = {0};
    unsigned int addr1,addr2,addr3,addr4;
    unsigned int number = 0;
    unsigned int entering_alg = 0;
    ngx_connection_t *c;

    c = s->connection;
    command = ngx_pcalloc(c->pool,size+1);
    if (command == NULL) {
        return NGX_OK;
    }

    ngx_memcpy(command,buf,size);

    /*check the buf ends with the \r\n */
    if (ngx_strncmp(command +size -1 -2,CRLF,2) != 0 ) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                "%s find a full sentence with \"\\r\\n\"",__func__);
        if (ngx_strstr(command,pasv) != NULL) {
            ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                "%s:Entering Passive Mode.%s",__func__,command);
            left_brace = ngx_strlchr(command,command + size -1,'(');
            right_brace = ngx_strlchr(command,command +size -1,')');
            if (left_brace == NULL || right_brace == NULL) {
                ngx_log_debug1(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                        "%s:Couldn't find the right pattern string.",__func__);
                ngx_pfree(c->pool,command);
                return 0;
            }
            entering_alg = 1;

        } else if (ngx_strstr(command,port) != NULL) {
            ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                "%s:Entering Port Mode.%s",__func__,command);
            left_brace = ngx_strlchr(command,command + size -1,' ');
            right_brace = ngx_strlchr(command,command +size -1,'\r');
            if (left_brace == NULL || right_brace == NULL) {
                ngx_log_debug1(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                        "%s:Couldn't find the right pattern string.",__func__);
                ngx_pfree(c->pool,command);
                return 0;
            }
            entering_alg = 2;
        }

        if (entering_alg > 0) {
            ngx_int_t port_num = 0;
            ngx_uint_t try_times = 0;
            left_brace += 1;
            right_brace -= 1;
            if (ngx_stream_alg_ftp_get_peer_addr(s,left_brace,right_brace-left_brace+1) < 0){
                ngx_log_debug1(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                        "%s:Doesn't contain the right pattern for ip and port.",__func__);
                ngx_pfree(c->pool,command);
                return 0;
            }
            if (entering_alg == 1) {
                if (getsockname(fd, (struct sockaddr *)&sockaddr,&socklen) == -1) {
                    ngx_pfree(c->pool,command);
                    return NGX_OK;
                }
                ngx_inet_ntop(sockaddr.sin_family,(struct sockaddr *)&sockaddr.sin_addr,addr_str,INET_ADDRSTRLEN);
                ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                        "%s the address is %s.",__func__,addr_str);
                number = sscanf((const char *)addr_str,"%u.%u.%u.%u",&addr1,&addr2,&addr3,&addr4);
            }else {
                fd = s->upstream ->peer.connection->fd;
                if (getsockname(fd, (struct sockaddr *)&sockaddr,&socklen) == -1) {
                    ngx_pfree(c->pool,command);
                    return NGX_OK;
                }
                ngx_inet_ntop(sockaddr.sin_family,(struct sockaddr *)&sockaddr.sin_addr,addr_str,INET_ADDRSTRLEN);
                ngx_log_debug2(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                        "%s the address is %s.",__func__,addr_str);
                number = sscanf((const char *)addr_str,"%u.%u.%u.%u",&addr1,&addr2,&addr3,&addr4);
            }
            if(number != 4 ) {
                ngx_pfree(c->pool,command);
                return NGX_OK;
            }
            while (port_num <=0 && try_times++ < 5) {
                port_num = ngx_stream_alg_create_listening_port(s);
            }
            if (try_times >= 5 ) {
                ngx_log_debug1(NGX_LOG_DEBUG_STREAM,s->connection->log,0,
                        "%s allocate a new socket for data session failed.",__func__);
                ngx_pfree(c->pool,command);
                return NGX_OK;
            }
            if (entering_alg == 1) {
                new_buf = ngx_snprintf(buf,80,"227 Entering Passive Mode (%ud,%ud,%ud,%ud,%ud,%ud).\r\n",addr1,addr2,addr3,addr4,port_num/256,port_num%256);
            }else {
                new_buf = ngx_snprintf(buf,80,"PORT %ud,%ud,%ud,%ud,%ud,%ud\r\n",addr1,addr2,addr3,addr4,port_num/256,port_num%256);
            }
            number = new_buf - buf;
        }
    }

    ngx_pfree(c->pool,command);

    return number;

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
            ctx->alg_resolved_peer = NULL;
            ctx->alg_handler = ngx_stream_alg_ftp_process;

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
