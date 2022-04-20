#include <ndk.h>
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
    ngx_http_complex_value_t *name;
} ngx_http_evaluate_loc_conf_t;

typedef struct {
    ngx_flag_t precontent;
    ngx_flag_t rewrite;
} ngx_http_evaluate_main_conf_t;

ngx_module_t ngx_http_evaluate_module;

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_rewrite_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    *v = ngx_http_variable_null_value;
    return NGX_OK;
}

static char *ngx_http_evaluate_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_evaluate_loc_conf_t *elcf = conf;
    ngx_http_evaluate_location_t *location;
    if (elcf->location == NGX_CONF_UNSET_PTR && !(elcf->location = ngx_array_create(cf->pool, 1, sizeof(*location)))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_array_create"); return NGX_CONF_ERROR; }
    if (!(location = ngx_array_push(elcf->location))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
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
    ngx_http_evaluate_main_conf_t *emcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_evaluate_module);
    emcf->rewrite = 1;
    return NGX_CONF_OK;
}

static char *ngx_http_evaluate_redirect_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_evaluate_main_conf_t *emcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_evaluate_module);
    emcf->precontent = 1;
    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}

static ngx_command_t ngx_http_evaluate_commands[] = {
  { .name = ngx_string("evaluate"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    .set = ngx_http_evaluate_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("redirect"),
    .type = NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_evaluate_redirect_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_evaluate_loc_conf_t, name),
    .post = NULL },
    ngx_null_command
};

static ngx_int_t ngx_http_evaluate_post_subrequest_handler(ngx_http_request_t *r, void *data, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    ngx_http_evaluate_context_t *context = ngx_http_get_module_ctx(r->main, ngx_http_evaluate_module);
    ngx_http_evaluate_context_t *subcontext = ngx_http_get_module_ctx(r, ngx_http_evaluate_module);
    if (context->rc < NGX_HTTP_SPECIAL_RESPONSE) context->rc = rc;
    ngx_http_variable_value_t *value = r->variables + subcontext->index;
    value->len = 0;
    for (ngx_chain_t *cl = r->out; cl; cl = cl->next) {
        if (!ngx_buf_in_memory(cl->buf)) continue;
        value->len += cl->buf->last - cl->buf->pos;
    }
    if (!value->len) return rc;
    if (!(value->data = ngx_pnalloc(r->pool, value->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    u_char *p = value->data;
    for (ngx_chain_t *cl = r->out; cl; cl = cl->next) {
        if (!ngx_buf_in_memory(cl->buf)) continue;
        p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
    }
    value->not_found = 0;
    value->valid = 1;
    return rc;
}

static ngx_int_t ngx_http_evaluate_rewrite_handler(ngx_http_request_t *r) {
    ngx_http_evaluate_loc_conf_t *elcf = ngx_http_get_module_loc_conf(r, ngx_http_evaluate_module);
    if (elcf->location == NGX_CONF_UNSET_PTR) return NGX_DECLINED;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_evaluate_location_t *location = elcf->location->elts;
    ngx_http_evaluate_context_t *context = ngx_http_get_module_ctx(r, ngx_http_evaluate_module);
    if (!context) {
        if (!(context = ngx_pcalloc(r->pool, sizeof(*context)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        context->index = location[context->location].index;
        ngx_http_set_ctx(r, context, ngx_http_evaluate_module);
    }
    if (context->location == elcf->location->nelts) return context->rc < NGX_HTTP_SPECIAL_RESPONSE ? NGX_DECLINED : context->rc;
    ngx_str_t uri;
    if (ngx_http_complex_value(r, &location[context->location].cv, &uri) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_str_t args = r->args;
    ngx_uint_t flags = 0;
    if (ngx_http_parse_unsafe_uri(r, &uri, &args, &flags) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool, sizeof(*psr));
    if (!psr) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_palloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    psr->handler = ngx_http_evaluate_post_subrequest_handler;
    ngx_http_request_t *subrequest;
    if (ngx_http_subrequest(r, &uri, &args, &subrequest, psr, flags) == NGX_ERROR) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_subrequest == NGX_ERROR"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_http_evaluate_context_t *subcontext = ngx_pcalloc(r->pool, sizeof(*subcontext));
    if (!subcontext) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    subcontext->index = location[context->location].index;
    subcontext->location = context->location;
    ngx_http_set_ctx(subrequest, subcontext, ngx_http_evaluate_module);
    context->location++;
    return NGX_DONE;
}

static ngx_int_t ngx_http_evaluate_precontent_handler(ngx_http_request_t *r) {
    ngx_http_evaluate_loc_conf_t *elcf = ngx_http_get_module_loc_conf(r, ngx_http_evaluate_module);
    if (!elcf->name) return NGX_DECLINED;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_str_t name;
    if (ngx_http_complex_value(r, elcf->name, &name) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
    if (name.data[0] == '@') (void)ngx_http_named_location(r, &name); else {
        ngx_str_t args;
        ngx_http_split_args(r, &name, &args);
        (void)ngx_http_internal_redirect(r, &name, &args);
    }
    ngx_http_finalize_request(r, NGX_DONE);
    return NGX_DONE;
}

static ngx_int_t ngx_chain_add_copy_buf(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in) {
    ngx_chain_t *cl, **ll = chain;
    ngx_int_t rc = NGX_ERROR;
    for (cl = *chain; cl; cl = cl->next) ll = &cl->next;
    while (in) {
        if (!(cl = ngx_alloc_chain_link(pool))) goto ret;
        if (!(cl->buf = ngx_create_temp_buf(pool, in->buf->last - in->buf->pos))) goto ret;
        *cl->buf = *in->buf;
        in->buf->pos = in->buf->last;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }
    rc = NGX_OK;
ret:
    *ll = NULL;
    return rc;
}

static ngx_int_t ngx_http_evaluate_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    if (r == r->main) return ngx_http_next_body_filter(r, in);
    ngx_http_evaluate_context_t *subcontext = ngx_http_get_module_ctx(r, ngx_http_evaluate_module);
    if (!subcontext) return ngx_http_next_body_filter(r, in);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (ngx_chain_add_copy_buf(r->pool, &r->out, in) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_chain_add_copy_buf != NGX_OK"); return NGX_ERROR; }
    return NGX_OK;
}

static ngx_int_t ngx_http_evaluate_postconfiguration(ngx_conf_t *cf) {
    ngx_http_evaluate_main_conf_t *emcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_evaluate_module);
    if (emcf->precontent) {
        ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
        ngx_http_handler_pt *handler = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
        if (!handler) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_array_push"); return NGX_ERROR; }
        *handler = ngx_http_evaluate_precontent_handler;
    }
    if (emcf->rewrite) {
        ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
        ngx_http_handler_pt *handler = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
        if (!handler) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_array_push"); return NGX_ERROR; }
        *handler = ngx_http_evaluate_rewrite_handler;
        ngx_http_next_body_filter = ngx_http_top_body_filter;
        ngx_http_top_body_filter = ngx_http_evaluate_body_filter;
    }
    return NGX_OK;
}

static void *ngx_http_evaluate_create_main_conf(ngx_conf_t *cf) {
    ngx_http_evaluate_main_conf_t *emcf = ngx_pcalloc(cf->pool, sizeof(*emcf));
    if (!emcf) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
    return emcf;
}

static void *ngx_http_evaluate_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_evaluate_loc_conf_t *elcf = ngx_pcalloc(cf->pool, sizeof(*elcf));
    if (!elcf) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
    elcf->location = NGX_CONF_UNSET_PTR;
    return elcf;
}

static ngx_int_t ngx_conf_merge_array_value(ngx_array_t **conf, ngx_array_t **prev, void *cmp) {
    if (*conf == cmp || (*conf)->nelts == 0) {
        *conf = *prev;
    } else if (*prev != cmp && (*prev)->nelts) {
        if ((*conf)->size != (*prev)->size) return NGX_ERROR;
        ngx_uint_t orig_len = (*conf)->nelts;
        if (!ngx_array_push_n(*conf, (*prev)->nelts)) return NGX_ERROR;
        char *elts = (*conf)->elts;
        for (ngx_uint_t i = 0; i < orig_len; i++) {
            ngx_memcpy(elts + (*conf)->size * ((*conf)->nelts - 1 - i), elts + (*conf)->size * (orig_len - 1 - i), (*conf)->size);
        }
        char *prev_elts = (*prev)->elts;
        for (ngx_uint_t i = 0; i < (*prev)->nelts; i++) {
            ngx_memcpy(elts + (*prev)->size * i, prev_elts + (*prev)->size * i, (*prev)->size);
        }
    }
    return NGX_OK;
}

static char *ngx_http_evaluate_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_evaluate_loc_conf_t *prev = parent;
    ngx_http_evaluate_loc_conf_t *conf = child;
    if (ngx_conf_merge_array_value(&conf->location, &prev->location, NGX_CONF_UNSET_PTR) != NGX_OK) return NGX_CONF_ERROR;
    if (!conf->name) conf->name = prev->name;
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_evaluate_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = ngx_http_evaluate_postconfiguration,
    .create_main_conf = ngx_http_evaluate_create_main_conf,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_evaluate_create_loc_conf,
    .merge_loc_conf = ngx_http_evaluate_merge_loc_conf
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
