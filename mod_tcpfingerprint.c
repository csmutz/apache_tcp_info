/* 
**  mod_tcpfingerprint.c -- module for collecting SAVED_SYN and TCP_INFO data from kernel
*/ 

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_optional.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_connection.h"
#include "http_log.h"
#include "http_request.h"

#include "ap_config.h"
#include "ap_listen.h"
#include "ap_expr.h"

#include "mod_log_config.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <unistd.h>

#define strcEQ(s1,s2)    (strcasecmp(s1,s2) == 0)
#define strIsEmpty(s)    (s == NULL || s[0] == '\0')

extern module AP_MODULE_DECLARE_DATA tcpfingerprint_module;

static const char *const fingerprint_vars[] = 
{
    "FINGERPRINT_IP_TTL",
    "FINGERPRINT_IP_DF",
    "FINGERPRINT_IP_ECN",
    "FINGERPRINT_TCP_WSIZE",
    "FINGERPRINT_TCP_WSCALE",
    "FINGERPRINT_TCP_MSS",
    "FINGERPRINT_TCP_ECN",
    "FINGERPRINT_TCP_OPTIONS",

    "FINGERPRINT_TCP_RTT",

    //Currently not collected
    //"FINGERPRINT_ACCEPT_TIME",
    NULL
};

typedef struct
{
    const unsigned char *pkt_data;
    int pkt_len;
    const struct iphdr *ip;
    const struct ip6_hdr *ip6;
    const struct tcphdr *tcp;
    int tcp_offset;
    int tcp_length;
    int ip_version;
} syn_packet_t;

typedef struct
{
    int export_envvars;
    int export_envvars_set;
    int export_savedsyn;
    int export_savedsyn_set;
    int export_tcpinfo;
    int export_tcpinfo_set;
} fingerprint_dir_conf_t;

typedef struct
{
    int get_savedsyn;
    int get_savedsyn_set;
    int get_tcpinfo;
    int get_tcpinfo_set;
} fingerprint_server_conf_t;


typedef struct
{
    const struct tcp_info *tcp_info;
    int tcp_info_len;
    syn_packet_t *saved_syn;
    //not currently collected
    //apr_time_t accept_ts;
} fingerprint_conn_data_t;


static int parse_pkt(request_rec *r, syn_packet_t *syn)
{
    int ip6_offset = sizeof(struct ip6_hdr);
    struct ip6_ext *ext;
    
    if (syn->ip_version > 0 || syn->ip_version == -1)
    {
        return syn->ip_version;
    }

    //make sure pkt at least contains both ipv4 and ipv6 length and proto
    if (syn->pkt_len >= 10)
    {
        syn->ip_version = (syn->pkt_data[0] & 0xF0) >> 4;
    }
    
    if (syn->ip_version == 4)
    {
        syn->ip = (struct iphdr *)syn->pkt_data;
        syn->tcp_offset = syn->ip->ihl * 4;
    }
    
    if (syn->ip_version == 6)
    {
        syn->ip6 = (struct ip6_hdr *)syn->pkt_data;
        if (syn->ip6->ip6_nxt == IPPROTO_TCP)
        {
            syn->tcp_offset = ip6_offset;
        } else
        {
            ext = (struct ip6_ext *)(&(syn->pkt_data[ip6_offset]));
            while (ip6_offset < syn->pkt_len - 8)
            {
                ip6_offset += (ext->ip6e_len + 1) * 8;
                if (ext->ip6e_nxt == IPPROTO_TCP)
                {
                    syn->tcp_offset = ip6_offset;
                } else
                {
                    ext = (struct ip6_ext *)(&(syn->pkt_data[ip6_offset]));
                } 
            }
        }
    }
    
    if (!(syn->ip_version == 4 || syn->ip_version == 6))
    {
        syn->ip_version = -1;
        syn->tcp_offset = 0;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Error parsing SYN packet: IP header not found");
    }

    if (syn->tcp_offset > 0)
    {
        if (syn->tcp_offset <= syn->pkt_len - 20)
        {
            syn->tcp = (struct tcphdr *)(&(syn->pkt_data[syn->tcp_offset]));
            if (syn->pkt_len > syn->tcp_offset + (syn->tcp->th_off * 5))
            {
                syn->pkt_len = syn->tcp_offset + (syn->tcp->th_off * 5);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Error parsing SYN packet: packet longer than TCP header length, truncating");
            }
        } else
        {
            syn->ip_version = -1;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Error parsing SYN packet: packet shorter than TCP header");
        }
    }
    return syn->ip_version;
}

static char *fingerprint_var_tcpinfo(fingerprint_conn_data_t *data, request_rec *r, char *var)
{
    char *value = NULL;
    if (data->tcp_info)
    {
        //TODO: check length of tcp_info to make sure values are included?
        if (strcEQ(var, "FINGERPRINT_TCP_RTT"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_rtt);
        if (strcEQ(var, "FINGERPRINT_TCP_INFO"))
        {
            value = apr_palloc(r->pool, data->tcp_info_len * 2 + 1);
            ap_bin2hex(data->tcp_info, data->tcp_info_len, value);
            return value;
        }
    }
    return NULL;
}

static char *fingerprint_var_syn_options(fingerprint_conn_data_t *data, request_rec *r)
{
    char ret[200];
    int i = data->saved_syn->tcp_offset + 20;
    int ret_i = 0;
    unsigned char opt;

    while(i < data->saved_syn->pkt_len)
    {
        opt = data->saved_syn->pkt_data[i];
        //add opt to string
        ret_i += apr_snprintf(ret + ret_i, (200-ret_i), "%i,", (int)opt);

        if ((opt > 1) && (i + 1 < data->saved_syn->pkt_len) && (data->saved_syn->pkt_data[i+1] != 0))
        {
            i += data->saved_syn->pkt_data[i+1];
        } else
        {
            i++;
        }
    }
    if (ret_i > 0)
    {
        ret[ret_i - 1] = '\0';
        return apr_pstrndup(r->pool, ret, ret_i);
    }   
    return NULL;
}

static char *fingerprint_var_syn_option(fingerprint_conn_data_t *data, request_rec *r, unsigned char var)
{
    int i = data->saved_syn->tcp_offset + 20;
    unsigned char opt;
    while(i < data->saved_syn->pkt_len)
    {
        opt = data->saved_syn->pkt_data[i];
        if ((opt > 1) && (i + 1 < data->saved_syn->pkt_len) && (data->saved_syn->pkt_data[i+1] != 0))
        {
            if (var == opt)
            {
                if (var == 3)
                {
                    return (char *)apr_psprintf(r->pool, "%u", (unsigned int)data->saved_syn->pkt_data[i+2]);
                }
                if (var == 2)
                {
                    return (char *)apr_psprintf(r->pool, "%u", (unsigned int)(data->saved_syn->pkt_data[i+2] * 256 + data->saved_syn->pkt_data[i+3]));
                }
            }
            i += data->saved_syn->pkt_data[i+1];
        } else
        {
            i++;
        }
    }
    return NULL;
}

static char *fingerprint_var_syn(fingerprint_conn_data_t *data, request_rec *r, char *var)
{
    //if parse_pkt returns 4 or 6 we are garunteed to have valid values in saved_syn
    if (data->saved_syn && (parse_pkt(r, data->saved_syn) > 0))
    {
        if (strcEQ(var, "FINGERPRINT_IP_TTL"))
        {
            if (data->saved_syn->ip_version == 4)
            {
                return (char *)apr_psprintf(r->pool, "%u", (unsigned int)data->saved_syn->ip->ttl);
            }
            if (data->saved_syn->ip_version == 6)
            {
                return (char *)apr_psprintf(r->pool, "%u", (unsigned int)data->saved_syn->ip6->ip6_hlim);
            }
        }
        if (strcEQ(var, "FINGERPRINT_IP_ECN"))
        {
            if (data->saved_syn->ip_version == 4)
            {
                return (char *)apr_psprintf(r->pool, "%u", (unsigned int)(data->saved_syn->ip->tos & 0x03));
            }
            if (data->saved_syn->ip_version == 6)
            {
                return (char *)apr_psprintf(r->pool, "%u", (unsigned int)((data->saved_syn->pkt_data[1] & 0x03) >> 4));
            }
        }
        if (strcEQ(var, "FINGERPRINT_TCP_WSIZE"))
        {
            return (char *)apr_psprintf(r->pool, "%u", (unsigned int)ntohs(data->saved_syn->tcp->window));
        }
        if (strcEQ(var, "FINGERPRINT_TCP_ECN"))
        {
            return (char *)apr_psprintf(r->pool, "%u", (unsigned int)data->saved_syn->tcp->res2);
        }
        if (strcEQ(var, "FINGERPRINT_TCP_WSCALE"))
        {
            return fingerprint_var_syn_option(data, r, 3);
        }
        if (strcEQ(var, "FINGERPRINT_TCP_MSS"))
        {
            return fingerprint_var_syn_option(data, r, 2);
        }
        if (strcEQ(var, "FINGERPRINT_TCP_OPTIONS"))
        {
            return fingerprint_var_syn_options(data, r);
        }
    }
    return NULL;
}

//get a variable by name
static char *fingerprint_var(request_rec *r, char *var)
{
    conn_rec *c = r->connection;
    fingerprint_conn_data_t *data = NULL;

    char *value = NULL;

    //always use master connection?
    if (c->master)
    {
        c = c->master;
    }

    data = (fingerprint_conn_data_t *) ap_get_module_config(c->conn_config, &tcpfingerprint_module);

    if (strcEQ(var, "FINGERPRINT_TCP_WSIZE"))
        return fingerprint_var_syn(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_MSS"))
        return fingerprint_var_syn(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_WSCALE"))
        return fingerprint_var_syn(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_ECN"))
        return fingerprint_var_syn(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_OPTIONS"))
        return fingerprint_var_syn(data, r, var);
    if (strcEQ(var, "FINGERPRINT_IP_TTL"))
        return fingerprint_var_syn(data, r, var);
    if (strcEQ(var, "FINGERPRINT_IP_ECN"))
        return fingerprint_var_syn(data, r, var);

    if (strcEQ(var, "FINGERPRINT_TCP_RTT"))
        return fingerprint_var_tcpinfo(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_INFO"))
        return fingerprint_var_tcpinfo(data, r, var);

    if (strcEQ(var, "FINGERPRINT_SAVED_SYN"))
    {
        if (data->saved_syn)
        {
            if (data->saved_syn->pkt_len > 0)
            {
                value = apr_palloc(r->pool, data->saved_syn->pkt_len * 2 + 1);
                ap_bin2hex(data->saved_syn->pkt_data, data->saved_syn->pkt_len, value);
                return value;
            }
        }
    }
    //Disabled until accept time can be collected reliably
    //if (strcEQ(var, "FINGERPRINT_ACCEPT_TIME"))
    //{
    //    return apr_psprintf(r->pool, "%" APR_INT64_T_FMT, data->accept_ts);
    //}
    return NULL;
}    
    
static const char *fingerprint_log_handler(request_rec *r, char *var)
{
    return fingerprint_var(r, var);
}

void fingerprint_log_register(apr_pool_t *p)
{
    APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

    if (log_pfn_register)
    {
        log_pfn_register(p, "g", fingerprint_log_handler, 0);
    }
}

static int fingerprint_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    //set callback for customlog
    fingerprint_log_register(pconf);
    return OK;
}

static int fingerprint_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    //set save_syn on all listeners
    ap_listen_rec *lr;
    int listen_sd;
    int res;
    int save_syn = 1;
    apr_status_t stat = 0;

    for(lr = ap_listeners; lr; lr = lr->next) 
    {
        //if (lr->bind_addr)
        //{
        //    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "listen port: %i", (int) lr->bind_addr->port);
        //}
        apr_os_sock_get(&listen_sd, lr->sd);
        res = setsockopt(listen_sd, IPPROTO_TCP, TCP_SAVE_SYN, &save_syn, sizeof(save_syn));
        if (res < 0)
        {
            stat = apr_get_netos_error();
            ap_log_error(APLOG_MARK, APLOG_ERR, stat, s, "Failed to set TCP_SAVE_SYN on listener for port: %i", (int) lr->bind_addr->port);
        } 
    }
}

static int fingerprint_pre_connection(conn_rec *c, void *csd)
{
    fingerprint_server_conf_t *server_conf = ap_get_module_config(c->base_server->module_config, &tcpfingerprint_module);
    fingerprint_conn_data_t *data = NULL;
    struct tcp_info ti;
    int ti_length = 0;
    int res = 0;
    apr_status_t stat = 0;
    int sd = 0;
    int nonblock = 0;
    char syn_packet[196];
    int syn_length = 196;
    
    apr_os_sock_get(&sd, csd);

    //only add fingerprint into to master connection, if this is a slave connection, do nothing.
    if ((!(c->master)) && (server_conf->get_tcpinfo || server_conf->get_savedsyn))
    {
        data = apr_pcalloc(c->pool, sizeof(*data));
        ap_set_module_config(c->conn_config, &tcpfingerprint_module, data);

        ti_length = sizeof(ti);
                
        stat = apr_socket_opt_get(csd, APR_SO_NONBLOCK, &nonblock);
        if (stat != APR_SUCCESS)
        {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "Failed to get socket nonblock status");
        }

        if (nonblock)
        {
            stat = apr_socket_opt_set(csd, APR_SO_NONBLOCK, 0);
            if (stat != APR_SUCCESS)
            {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "Failed to temporarily disable socket nonblock");
            }
        }

        if (server_conf->get_tcpinfo)
        {
            res = getsockopt(sd, IPPROTO_TCP, TCP_INFO, &ti, (socklen_t *)&ti_length);
            if (res < 0)
            {
                stat = apr_get_netos_error();
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, stat, c, "error getting TCP_INFO");
            } else
            {
                //check ti len?--right now we only used RTT which should be safe--no length check needed
                data->tcp_info = apr_pmemdup(c->pool, &ti, ti_length);
                data->tcp_info_len = ti_length;
            }
        }
        
        if (server_conf->get_savedsyn)
        {
            res = getsockopt(sd, IPPROTO_TCP, TCP_SAVED_SYN, &syn_packet, (socklen_t *)&syn_length);
            if (res < 0)
            {
                stat = apr_get_netos_error();
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, stat, c, "error getting TCP_SAVED_SYN");
            } else
            {
                data->saved_syn = apr_pcalloc(c->pool, sizeof(syn_packet_t));
                data->saved_syn->pkt_data = apr_pmemdup(c->pool, &syn_packet, syn_length);
                data->saved_syn->pkt_len = syn_length;
            }
        }

        if (nonblock)
        {
            stat = apr_socket_opt_set(csd, APR_SO_NONBLOCK, 1);
            if (stat != APR_SUCCESS)
            {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "Failed to re-enable socket nonblock");
            }
        }

    }
    return OK;
}

static int fingerprint_fixups(request_rec* r)
{
    apr_table_t *env = r->subprocess_env;
    char *var, *val = "";
    int i;
    fingerprint_dir_conf_t  *dir_conf = (fingerprint_dir_conf_t *) ap_get_module_config(r->per_dir_config, &tcpfingerprint_module);   
 
    if (dir_conf->export_envvars)
    {
        for (i = 0; fingerprint_vars[i]; i++)
        {
            var = (char *)fingerprint_vars[i];
            val = fingerprint_var(r, var);
            if (!strIsEmpty(val)) 
            {
                apr_table_setn(env, var, val);
            }
        }
    }

    if (dir_conf->export_tcpinfo)
    {
        var = "FINGERPRINT_TCP_INFO";
        val = fingerprint_var(r, var);
        if (!strIsEmpty(val))
        {
            apr_table_setn(env, var, val);
        }
    }

    if (dir_conf->export_savedsyn)
    {
        var = "FINGERPRINT_SAVED_SYN";
        val = fingerprint_var(r, var);
        if (!strIsEmpty(val))
        {
            apr_table_setn(env, var, val);
        }
    }

    return OK;
}

static void tcpfingerprint_register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(fingerprint_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(fingerprint_post_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_pre_connection(fingerprint_pre_connection, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(fingerprint_fixups, NULL, NULL, APR_HOOK_FIRST);
}

static const char *enable_envvars(cmd_parms *cmd, void *config, int flag)
{
    fingerprint_dir_conf_t *dir_conf = (fingerprint_dir_conf_t *)config;
    dir_conf->export_envvars = (flag ? 1 : 0);
    dir_conf->export_envvars_set = 1;   

    return NULL;
}

static const char *enable_envtcpinfo(cmd_parms *cmd, void *config, int flag)
{
    fingerprint_dir_conf_t *dir_conf = (fingerprint_dir_conf_t *)config;
    dir_conf->export_tcpinfo = (flag ? 1 : 0);
    dir_conf->export_tcpinfo_set = 1;
    return NULL;
}

static const char *enable_envsavedsyn(cmd_parms *cmd, void *config, int flag)
{
    fingerprint_dir_conf_t *dir_conf = (fingerprint_dir_conf_t *)config;
    dir_conf->export_savedsyn = (flag ? 1 : 0); 
    dir_conf->export_savedsyn_set = 1;
    return NULL;
}

static const char *enable_gettcpinfo(cmd_parms *cmd, void *dummy, int flag)
{
    fingerprint_server_conf_t *server_conf = ap_get_module_config(cmd->server->module_config, &tcpfingerprint_module);
    server_conf->get_tcpinfo = (flag ? 1 : 0);
    server_conf->get_tcpinfo_set = 1;
    return NULL;
}

static const char *enable_getsavedsyn(cmd_parms *cmd, void *dummy, int flag)
{
    fingerprint_server_conf_t *server_conf = ap_get_module_config(cmd->server->module_config, &tcpfingerprint_module);
    server_conf->get_savedsyn = (flag ? 1 : 0); 
    server_conf->get_savedsyn_set = 1;
    return NULL;
}

void *create_dir_conf(apr_pool_t *pool, char *context)
{
    fingerprint_dir_conf_t *dir_conf = apr_pcalloc(pool, sizeof(fingerprint_dir_conf_t));
    dir_conf->export_envvars = 0;
    dir_conf->export_envvars_set = 0;
    dir_conf->export_savedsyn = 0;
    dir_conf->export_savedsyn_set = 0;
    dir_conf->export_tcpinfo = 0;
    dir_conf->export_tcpinfo_set = 0;
    return dir_conf;
}

void *merge_dir_conf(apr_pool_t *pool, void *BASE, void *ADD) {
    fingerprint_dir_conf_t *base = (fingerprint_dir_conf_t *) BASE; 
    fingerprint_dir_conf_t *add = (fingerprint_dir_conf_t *) ADD;
    fingerprint_dir_conf_t *conf = (fingerprint_dir_conf_t *) create_dir_conf(pool, "Merged configuration");
    fingerprint_dir_conf_t *src = NULL; //switch between base or add based on which has values set

    //always inheret new configuration value if set
    src = (add->export_envvars_set) ? add : base;
    conf->export_envvars = src->export_envvars;
    conf->export_envvars_set = src->export_envvars_set;
    src = (add->export_savedsyn_set) ? add : base;
    conf->export_savedsyn = src->export_savedsyn;
    conf->export_savedsyn_set = src->export_savedsyn_set;
    src = (add->export_tcpinfo_set) ? add : base;
    conf->export_tcpinfo = src->export_tcpinfo;
    conf->export_tcpinfo_set = src->export_tcpinfo_set;
    return conf;
}

void *create_server_conf(apr_pool_t *pool, server_rec *s)
{
    fingerprint_server_conf_t *server_conf = apr_pcalloc(pool, sizeof(fingerprint_server_conf_t));
    server_conf->get_savedsyn = 1;
    server_conf->get_savedsyn_set = 0;
    server_conf->get_tcpinfo = 1;
    server_conf->get_tcpinfo_set = 0;
    return server_conf;
}

void *merge_server_conf(apr_pool_t *pool, void *BASE, void *ADD) {
    fingerprint_server_conf_t *base = (fingerprint_server_conf_t *) BASE;
    fingerprint_server_conf_t *add = (fingerprint_server_conf_t *) ADD;
    fingerprint_server_conf_t *conf = (fingerprint_server_conf_t *) create_server_conf(pool, NULL);
    fingerprint_server_conf_t *src = NULL; //switch between base or add based on which has values set

    //always inheret new configuration value if set
    src = (add->get_savedsyn_set) ? add : base;
    conf->get_savedsyn = src->get_savedsyn;
    conf->get_savedsyn_set = src->get_savedsyn_set;
    src = (add->get_tcpinfo_set) ? add : base;
    conf->get_tcpinfo = src->get_tcpinfo;
    conf->get_tcpinfo_set = src->get_tcpinfo_set;
    return conf;
}

static const command_rec tcpfingerprint_cmds[] =
{
    AP_INIT_FLAG("TCPFingerprintEnvVars", enable_envvars, NULL,
        ACCESS_CONF | OR_OPTIONS, "Enable creation of CGI environment variables ('on', 'off')"),
    AP_INIT_FLAG("TCPFingerprintEnvTCPInfo", enable_envtcpinfo, NULL,
        ACCESS_CONF | OR_OPTIONS, "Enable dump of raw TCP_INFO in environment variables ('on', 'off')"),
    AP_INIT_FLAG("TCPFingerprintEnvSavedSYN", enable_envsavedsyn, NULL,
        ACCESS_CONF | OR_OPTIONS, "Enable dump of raw SAVED_SYN in environment variables ('on', 'off')"),
   AP_INIT_FLAG("TCPFingerprintGetSavedSYN", enable_getsavedsyn, NULL,
        RSRC_CONF, "Enable collection of SAVED_SYN from kernel using getsockopt ('on', 'off')"),
   AP_INIT_FLAG("TCPFingerprintGetTCPInfo", enable_gettcpinfo, NULL,
        RSRC_CONF, "Enable collection of TCP_INFO from kernel using getsockopt ('on', 'off')"),

    { NULL }
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA tcpfingerprint_module = {
    STANDARD20_MODULE_STUFF, 
    create_dir_conf,
    merge_dir_conf,
    create_server_conf,
    merge_server_conf,
    tcpfingerprint_cmds,
    tcpfingerprint_register_hooks
};

