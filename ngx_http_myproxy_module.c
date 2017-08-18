#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
typedef struct
{
    ngx_str_t hello_string;
    ngx_int_t hello_start;
}ngx_http_myproxy_loc_conf_t;

typedef struct
{
    ngx_int_t status;
}ngx_http_myproxy_ctx_t;
*/

//upstream
typedef struct
{
    ngx_int_t proxy_start;
    ngx_http_upstream_conf_t upstream;
}ngx_http_myupstream_conf_t;

static ngx_str_t ngx_http_proxy_hide_headers[] =
{
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

typedef struct
{
    ngx_http_status_t status;
    ngx_str_t  backendServer;
} ngx_http_myupstream_ctx_t;

static ngx_int_t ngx_http_myproxy_init(ngx_conf_t *cf);
static void *ngx_http_myproxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_myproxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
//static char *ngx_http_hello_string(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_myproxy_start(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_myproxy_body_handler(ngx_http_request_t *r);
/*for upstream*/
static ngx_int_t myproxy_upstream_create_request(ngx_http_request_t *r);
static ngx_int_t myproxy_process_status_line(ngx_http_request_t *r);
static ngx_int_t myproxy_upstream_process_header(ngx_http_request_t *r);
static void myproxy_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
static ngx_int_t myproxy_upstream_process_header(ngx_http_request_t *r);
/*for encode*/
//static void myproxy_upstream_encode_request(ngx_http_request_t *r);

static ngx_command_t ngx_http_myproxy_commands[] = {
    {
        ngx_string("proxy_start"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_http_myproxy_start,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myupstream_conf_t, proxy_start),
        NULL 
    },

    /*
    {
        ngx_string("proxy_counter"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_http_hello_counter,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myproxy_loc_conf_t, hello_start),
        NULL 
    },
    */
    ngx_null_command
};


/*
* static u_char ngx_hello_default_string[] = "Default String: Hello, world!";
* */
//static int ngx_hello_visited_times = 0;

static ngx_http_module_t ngx_http_myproxy_module_ctx = {
    NULL,                          
    ngx_http_myproxy_init,           
    NULL,                          
    NULL,                          
    NULL,                          
    NULL,                        
    ngx_http_myproxy_create_loc_conf, 
    ngx_http_myproxy_merge_loc_conf
};


ngx_module_t ngx_http_myproxy_module = {
    NGX_MODULE_V1,
    &ngx_http_myproxy_module_ctx,    
    ngx_http_myproxy_commands,       
    NGX_HTTP_MODULE,               
    NULL,                          
    NULL,                          
    NULL,                          
    NULL,                         
    NULL,                         
    NULL,                          
    NULL,                          
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_myproxy_handler(ngx_http_request_t *r)
{
    ngx_int_t    rc;
    //ngx_buf_t   *b;
    //ngx_chain_t  out;
    ngx_http_myupstream_conf_t* my_conf;
    //u_char ngx_hello_string[1024] = {0};
    //ngx_uint_t content_length = 0;

    //ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "ngx_http_myproxy_handler is called!");

    ngx_http_myupstream_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_myproxy_module);
    if (myctx == NULL) {
        myctx = ngx_palloc(r->pool, sizeof(ngx_http_myupstream_ctx_t));
        if (myctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, myctx, ngx_http_myproxy_module);
    }

    /*允许接收用户请求方式
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    */

    my_conf = (ngx_http_myupstream_conf_t*)ngx_http_get_module_loc_conf(r,ngx_http_myproxy_module);

    if (my_conf->proxy_start == NGX_CONF_UNSET || my_conf->proxy_start == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }else{
        //设置上游服务器地址
        if(ngx_http_upstream_create(r) != NGX_OK){
            ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"ngx_http_upstream_create()failed");
            return NGX_ERROR;
        }
        ngx_http_upstream_t *u = r->upstream;
        u->conf = &my_conf->upstream;
        u->buffering = my_conf->upstream.buffering;
        u->resolved = (ngx_http_upstream_resolved_t*)ngx_pcalloc(r->pool,sizeof(ngx_http_upstream_resolved_t));
        if(u->resolved /*u->resolved_t*/ == NULL){
            ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"ngx_pcalloc resolved error. %s.",strerror(errno));
            return NGX_ERROR;
        }
        static struct sockaddr_in backendSockAddr;
        struct hostent *pHost = gethostbyname((char*)"www.baidu.com");
        //struct hostent *pHost = gethostbyname((char*)"localhost");
        if(pHost == NULL){
            ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"gethostbyname fail.%s",strerror(errno));
            return NGX_ERROR;
        }
        backendSockAddr.sin_family = AF_INET;
        //backendSockAddr.sin_port = htons((in_port_t)12345);
        backendSockAddr.sin_port = htons((in_port_t) 80);
        char *pDmsIP = inet_ntoa(*(struct in_addr*)(pHost->h_addr_list[0]));
        //char *pDmsIP = inet_ntoa(*(pHost->h_addr_list[0]));
        //backendSockAddr.sin_addr = *(struct in_addr*)(pHost->h_addr_list[0]);
        backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
        //inet_pton( AF_INET, pDmsIP, &backendSockAddr.sin_addr );
        myctx->backendServer.data = (u_char*)pDmsIP;
        myctx->backendServer.len = strlen(pDmsIP);
        u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
        u->resolved->socklen = sizeof(struct sockaddr_in);
        u->resolved->naddrs = 1;
        u->create_request = myproxy_upstream_create_request;
        u->process_header = myproxy_process_status_line;
        u->finalize_request = myproxy_upstream_finalize_request;
    }
   
    //处理加密客户端请求包头和包体
    //my_conf = ngx_http_get_module_loc_conf(r, ngx_http_myproxy_module);
    /*
    if (my_conf->hello_string.len == 0 )
    {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "hello_string is empty!");
        return NGX_DECLINED;
    }
    */
    //content_length = ngx_strlen(ngx_hello_string);

    /*丢弃包体*/
    /*
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    */

    /* set the 'Content-type' header */
    /*
    * *r->headers_out.content_type.len = sizeof("text/html") - 1;
    * *r->headers_out.content_type.data = (u_char *)"text/html";
    */

    /*
    ngx_str_set(&r->headers_out.content_type, "text/html");

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = content_length;
        return ngx_http_send_header(r);
    }
    */

    r->request_body_in_file_only = 1;
    r->request_body_in_persistent_file = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_myproxy_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    //ngx_http_finalize_request(r, NGX_DONE);
    return NGX_DONE;

    /*
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->pos = ngx_hello_string;
    b->last = ngx_hello_string + content_length;
    b->memory = 1;    
    b->last_buf = 1;  

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = content_length;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
    */
}

static void ngx_http_myproxy_body_handler(ngx_http_request_t *r)
{
    //u_char ngx_hello_string[1024] = {0};
    //ngx_uint_t content_length = 0;
    ngx_http_request_body_t *rb = r->request_body;
    ngx_str_t body;
    if (rb && rb->bufs) {
        body.data = (u_char*)rb->bufs->buf->pos;
        body.len = rb->bufs->buf->last - rb->bufs->buf->pos;
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "client body:%s", body.data);
        //ngx_http_finalize_request(r, NGX_OK);
        //return;
    }
    else{
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "request_body:%s", "request_body_NULL");
        //ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        //return;
    }

    //r->main->count++;
    ngx_http_upstream_init(r);
    //return NGX_DONE;
}

static void *ngx_http_myproxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_myupstream_conf_t* mycf = NULL;
    mycf = ngx_pcalloc(cf->pool, sizeof(ngx_http_myupstream_conf_t));
    if (mycf == NULL)
    {
        return NULL;
    }
    mycf->upstream.connect_timeout = 60000;
    mycf->upstream.send_timeout = 60000;
    mycf->upstream.read_timeout = 60000;
    mycf->upstream.store_access = 0600;
    mycf->upstream.buffering = 0;
    mycf->upstream.bufs.num = 8;
    mycf->upstream.bufs.size = ngx_pagesize;
    mycf->upstream.buffer_size = ngx_pagesize;

    mycf->upstream.busy_buffers_size = 2 * ngx_pagesize;
    mycf->upstream.temp_file_write_size = 2 * ngx_pagesize;

    mycf->upstream.max_temp_file_size = 1024 * 1024 * 1024;

    mycf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    mycf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    //ngx_str_null(&mycf->hello_string);
    mycf->proxy_start = NGX_CONF_UNSET;

    return mycf;
}

static char *ngx_http_myproxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_myupstream_conf_t* prev = parent;
    ngx_http_myupstream_conf_t* conf = child;

    ngx_hash_init_t hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";

    if(ngx_http_upstream_hide_headers_hash(cf,&conf->upstream, &prev->upstream, ngx_http_proxy_hide_headers, &hash)!= NGX_OK){
        return NGX_CONF_ERROR;
    }

    //ngx_conf_merge_str_value(conf->hello_string, prev->hello_string, ngx_hello_default_string);
    ngx_conf_merge_value(conf->proxy_start, prev->proxy_start, 0);

    return NGX_CONF_OK;
}

/*
static char *ngx_http_hello_string(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_myupstream_conf_t* local_conf;


    local_conf = conf;
    char* rv = ngx_conf_set_str_slot(cf, cmd, conf);

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "hello_string:%s", local_conf->hello_string.data);

    return rv;
}
*/

static char *ngx_http_myproxy_start(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_myupstream_conf_t* local_conf;

    local_conf = conf;

    char* rv = NULL;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);


    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "hello_start:%d", local_conf->proxy_start);
    return rv;
}

static ngx_int_t ngx_http_myproxy_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_myproxy_handler;

    return NGX_OK;
}

static ngx_int_t myproxy_upstream_create_request(ngx_http_request_t *r)
{
    static ngx_str_t backendQueryLine=ngx_string("GET http://localhost:12345/index.html HTTP/1.1\r\nConnection: close\r\n\r\n"); 
    //static ngx_str_t backendQueryLine=ngx_string("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); 
    ngx_int_t queryLinelen = backendQueryLine.len; 
    ngx_buf_t *b = ngx_create_temp_buf(r->pool,queryLinelen); 
    /*
    ngx_buf_t *b;
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if(b == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    //out.buf = b;
    //out.next = NULL;

    //b->pos = elcf->ed.data;
    //b->last = elcf->ed.data + (elcf->ed.len);
    ngx_memcpy(b->pos ,backendQueryLine.data ,backendQueryLine.len);
    b->last = b->pos+queryLinelen; 
    b->memory = 1;
    b->last_buf = 1;
    */

    if(b == NULL){ 
        return NGX_ERROR; 
    } 

    ngx_memcpy(b->pos ,backendQueryLine.data ,backendQueryLine.len);
    b->last = b->pos+queryLinelen; 

    r->upstream->request_bufs=ngx_alloc_chain_link(r->pool); 
    if(r->upstream->request_bufs == NULL){ 
        return NGX_ERROR; 
    } 
    r->upstream->request_bufs->buf = b; 
    r->upstream->request_bufs->next = NULL; 

    r->upstream->request_sent = 0; 
    r->upstream->header_sent = 0; 

    r->header_hash = 1; 

    return NGX_OK; 
}

static ngx_int_t myproxy_process_status_line(ngx_http_request_t *r)
{
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u;

    ngx_http_myupstream_ctx_t *ctx = ngx_http_get_module_ctx(r,ngx_http_myproxy_module);
    if(ctx == NULL){
        return NGX_ERROR;
    }

    u = r->upstream;

    /*tu*/
    /*
    ngx_str_t temp;
    temp.data = ngx_pnalloc(r->pool,u->buffer.last - u->buffer.pos); 
    if(temp.data == NULL){ 
        return NGX_ERROR; 
    }
    ngx_memcpy(temp.data ,u->buffer.pos ,u->buffer.last - u->buffer.pos);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP,r->connection->log,0,"this is debug");
    ngx_log_error(NGX_LOG_DEBUG,r->connection->log,0,"this is error");
    ngx_log_debug(NGX_LOG_DEBUG_HTTP,r->connection->log,0,(const char*)temp.data);
    ngx_log_error(NGX_LOG_DEBUG,r->connection->log,0,(const char*)temp.data);
    */
    /*tu*/

    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

    if(rc == NGX_AGAIN){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"Don't get full response header");
        return rc;
    }

    if(rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"upstream sent no valid HTTP/1.0 header");
        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;

        return NGX_OK;
    }

    if(u->state){
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_palloc(r->pool,len);
    if(u->headers_in.status_line.data == NULL){
        return NGX_ERROR;
    }
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);
    u->process_header = myproxy_upstream_process_header;
    return myproxy_upstream_process_header(r);
}

static ngx_int_t myproxy_upstream_process_header(ngx_http_request_t *r)
{
    ngx_int_t rc; 
    ngx_table_elt_t *h; 
    ngx_http_upstream_header_t *hh; 
    ngx_http_upstream_main_conf_t *umcf; 

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module); 
    for( ; ; ){ 
        rc = ngx_http_parse_header_line(r,&r->upstream->buffer,1); 
        if(rc == NGX_OK){ 
            h = ngx_list_push(&r->upstream->headers_in.headers); 
            if(h == NULL){ 
            return NGX_ERROR; 
            } 
            h->hash = r->header_hash; 
            h->key.len = r->header_name_end - r->header_name_start; 
            h->value.len = r->header_end - r->header_start; 


            h->key.data = ngx_pnalloc(r->pool,h->key.len + 1 + h->value.len + 1 + h->key.len); 
            if(h->key.data == NULL){ 
                return NGX_ERROR; 
            } 
            h->value.data = h->key.data + h->key.len +1; 
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1; 


            ngx_memcpy(h->key.data,r->header_name_start,h->key.len); 
            h->key.data[h->key.len] = '\0'; 


            ngx_memcpy(h->value.data,r->header_start,h->value.len); 
            h->key.data[h->value.len] = '\0'; 


            if(h->key.len == r->lowcase_index){ 
                ngx_memcpy(h->lowcase_key,r->lowcase_header,h->key.len); 
            }else{ 
                ngx_strlow(h->lowcase_key,h->key.data,h->key.len); 
            } 

            hh = ngx_hash_find(&umcf->headers_in_hash,h->hash,h->lowcase_key,h->key.len); 

            if(hh && hh->handler(r,h,hh->offset)!=NGX_OK){ 
                return NGX_ERROR; 
            } 
            continue; 
        } 
        if(rc == NGX_HTTP_PARSE_HEADER_DONE){ 
            if(r->upstream->headers_in.server == NULL){ 
                h = ngx_list_push(&r->upstream->headers_in.headers); 
                if(h == NULL){ 
                    return NGX_ERROR; 
                } 
                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r'); 
                ngx_str_set( &h->key,"Server"); 
                ngx_str_null( &h->value); 
                h->lowcase_key = (u_char *)"server"; 
            } 
            if(r->upstream->headers_in.date == NULL){ 
                    h = ngx_list_push(&r->upstream->headers_in.headers); 
                if(h == NULL){ 
                    return NGX_ERROR; 
            } 
                h->hash = ngx_hash(ngx_hash(ngx_hash('d','a'),'t'),'e'); 
                ngx_str_set(&h->key,"Date"); 
                ngx_str_null(&h->value); 
                h->lowcase_key = (u_char *)"date"; 
            } 
            return NGX_OK; 
        } 
        if(rc == NGX_AGAIN){ 
            return NGX_AGAIN; 
        } 
        ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"upstream sent invalid header"); 

        return NGX_HTTP_UPSTREAM_INVALID_HEADER; 
    }
}

static void myproxy_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_finalize_request(r, NGX_DONE);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "myproxy_upstream_finalize_request");
    return;
}

/*
static void myproxy_upstream_encode_request(ngx_http_request_t *r)
{
}
*/

