#include <ngx_http.h>

typedef struct {
    ngx_int_t rc;
    ngx_uint_t index;
    ngx_uint_t location;
} ngx_http_evaluate_context_t;

typedef struct {
    ngx_http_complex_value_t cv;
    ngx_uint_t index;
} ngx_http_evaluate_location_t;

typedef struct {
    ngx_array_t *location;
} ngx_http_evaluate_loc_conf_t;

typedef struct {
    ngx_flag_t enable;
} ngx_http_evaluate_main_conf_t;

ngx_module_t ngx_http_evaluate_module;

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static char *ngx_http_evaluate_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_evaluate_loc_conf_t *loc_conf = conf;
    ngx_http_evaluate_location_t *location;
    if (loc_conf->location == NGX_CONF_UNSET_PTR && !(loc_conf->location = ngx_array_create(cf->pool, 1, sizeof(*location)))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_array_create"); return NGX_CONF_ERROR; }
    if (!(location = ngx_array_push(loc_conf->location))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(location, sizeof(*location));
    ngx_str_t *args = cf->args->elts;
    ngx_str_t name = args[1];
    if (name.data[0] != '$') { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: invalid variable name", &cmd->name); return NGX_CONF_ERROR; }
    name.len--;
    name.data++;
    ngx_http_variable_t *variable = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (!variable) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_http_add_variable", &cmd->name); return NGX_CONF_ERROR; }
    if (!(location->index = ngx_http_get_variable_index(cf, &name))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_http_get_variable_index", &cmd->name); return NGX_CONF_ERROR; }
    if (!variable->get_handler && ngx_strncasecmp(name.data, (u_char *) "arg_", 4) && ngx_strncasecmp(name.data, (u_char *) "cookie_", 7) && ngx_strncasecmp(name.data, (u_char *) "http_", 5) && ngx_strncasecmp(name.data, (u_char *) "sent_http_", 10) && ngx_strncasecmp(name.data, (u_char *) "upstream_http_", 14)) {
        variable->get_handler = ngx_http_rewrite_var;
        variable->data = location->index;
    }
    ngx_str_t value = args[2];
    ngx_http_compile_complex_value_t ccv = {cf, &value, &location->cv, 0, 0, 0};
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_http_compile_complex_value != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
    ngx_http_evaluate_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_evaluate_module);
    main_conf->enable = 1;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_evaluate_commands[] = {
  { .name = ngx_string("evaluate"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    .set = ngx_http_evaluate_command,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
    ngx_null_command
};

static ngx_int_t ngx_http_evaluate_post_subrequest_handler(ngx_http_request_t *r, void *data, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    ngx_http_evaluate_context_t *context = ngx_http_get_module_ctx(r->main, ngx_http_evaluate_module);
    if (context->rc < NGX_HTTP_SPECIAL_RESPONSE) context->rc = rc;
    return rc;
}

static ngx_int_t ngx_http_evaluate_handler(ngx_http_request_t *r) {
    ngx_http_evaluate_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_evaluate_module);
    if (loc_conf->location == NGX_CONF_UNSET_PTR) return NGX_DECLINED;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_evaluate_location_t *location = loc_conf->location->elts;
    ngx_http_evaluate_context_t *context = ngx_http_get_module_ctx(r, ngx_http_evaluate_module);
    if (!context) {
        if (!(context = ngx_pcalloc(r->pool, sizeof(*context)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        context->index = location[context->location].index;
        ngx_http_set_ctx(r, context, ngx_http_evaluate_module);
    }
    if (context->location == loc_conf->location->nelts) return context->rc < NGX_HTTP_SPECIAL_RESPONSE ? NGX_DECLINED : context->rc;
    ngx_str_t uri;
    if (ngx_http_complex_value(r, &location[context->location].cv, &uri) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_str_t args = r->args;
    ngx_uint_t flags = 0;
    if (ngx_http_parse_unsafe_uri(r, &uri, &args, &flags) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    flags |= NGX_HTTP_SUBREQUEST_WAITED;
    ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool, sizeof(*psr));
    if (!psr) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_palloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    psr->handler = ngx_http_evaluate_post_subrequest_handler;
    ngx_http_request_t *subrequest;
    if (ngx_http_subrequest(r, &uri, &args, &subrequest, psr, flags) == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_subrequest == NGX_ERROR"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_http_evaluate_context_t *subcontext = ngx_pcalloc(r->pool, sizeof(*subcontext));
    if (!subcontext) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    subcontext->index = context->index;
    subcontext->index = location[context->location].index;
    subcontext->location = context->location;
    ngx_http_set_ctx(subrequest, subcontext, ngx_http_evaluate_module);
    context->location++;
    return NGX_DONE;
}

static ngx_int_t ngx_http_evaluate_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    if (r == r->main) return ngx_http_next_body_filter(r, in);
    ngx_http_evaluate_context_t *subcontext = ngx_http_get_module_ctx(r, ngx_http_evaluate_module);
    if (!subcontext) return ngx_http_next_body_filter(r, in);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_variable_value_t *value = r->variables + subcontext->index;
    for (ngx_chain_t *cl = in; cl; cl = cl->next) {
        if (!ngx_buf_in_memory(cl->buf)) continue;
        value->len += cl->buf->last - cl->buf->pos;
    }
    if (!value->len) return ngx_http_next_body_filter(r, in);
    if (!(value->data = ngx_pnalloc(r->pool, value->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    u_char *p = value->data;
    size_t len;
    for (ngx_chain_t *cl = in; cl; cl = cl->next) {
        if (!ngx_buf_in_memory(cl->buf)) continue;
        if (!(len = cl->buf->last - cl->buf->pos)) continue;
        p = ngx_copy(p, cl->buf->pos, len);
    }
    value->not_found = 0;
    value->valid = 1;
    return NGX_OK;
}

static ngx_int_t ngx_http_evaluate_postconfiguration(ngx_conf_t *cf) {
    ngx_http_evaluate_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_evaluate_module);
    if (!main_conf->enable) return NGX_OK;
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt *handler = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (!handler) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_array_push"); return NGX_ERROR; }
    *handler = ngx_http_evaluate_handler;
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_evaluate_body_filter;
    return NGX_OK;
}

static void *ngx_http_evaluate_create_main_conf(ngx_conf_t *cf) {
    ngx_http_evaluate_main_conf_t *main_conf = ngx_pcalloc(cf->pool, sizeof(*main_conf));
    if (!main_conf) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
    return main_conf;
}

static void *ngx_http_location_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_evaluate_loc_conf_t *loc_conf = ngx_pcalloc(cf->pool, sizeof(*loc_conf));
    if (!loc_conf) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
    loc_conf->location = NGX_CONF_UNSET_PTR;
    return loc_conf;
}

static char *ngx_http_location_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_evaluate_loc_conf_t *prev = parent;
    ngx_http_evaluate_loc_conf_t *conf = child;
    if (ngx_conf_merge_array_value(&conf->location, &prev->location, NGX_CONF_UNSET_PTR) != NGX_OK) return NGX_CONF_ERROR;
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_evaluate_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = ngx_http_evaluate_postconfiguration,
    .create_main_conf = ngx_http_evaluate_create_main_conf,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_location_create_loc_conf,
    .merge_loc_conf = ngx_http_location_merge_loc_conf
};

ngx_module_t ngx_http_evaluate_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_evaluate_ctx,
    .commands = ngx_http_evaluate_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
