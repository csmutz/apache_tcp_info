/* 
**  mod_tcpfingerprint.c -- module for collecting TCP fingerprinting data from kernel
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

    "FINGERPRINT_TCP_SNDWND",
    "FINGERPRINT_TCP_RCVWND",
    "FINGERPRINT_TCP_RTT",
    "FINGERPRINT_TCP_MINRTT",
    "FINGERPRINT_TCP_RCVRTT",
    "FINGERPRINT_TCP_LASTDATARECV",
    "FINGERPRINT_TCP_LASTACKRECV",
    "FINGERPRINT_TCP_SNDMSS",
    "FINGERPRINT_TCP_RCVMSS",
    "FINGERPRINT_TCP_ADVMSS",
    "FINGERPRINT_TCP_PMTU",

    "FINGERPRINT_ACCEPT_TIME",
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


typedef struct {
	uint8_t	tcpi_state;
	uint8_t	tcpi_ca_state;
	uint8_t	tcpi_retransmits;
	uint8_t	tcpi_probes;
	uint8_t	tcpi_backoff;
	uint8_t	tcpi_options;
	uint8_t	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
	uint8_t	tcpi_delivery_rate_app_limited:1, tcpi_fastopen_client_fail:2;

	uint32_t	tcpi_rto;
	uint32_t	tcpi_ato;
	uint32_t	tcpi_snd_mss;
	uint32_t	tcpi_rcv_mss;

	uint32_t	tcpi_unacked;
	uint32_t	tcpi_sacked;
	uint32_t	tcpi_lost;
	uint32_t	tcpi_retrans;
	uint32_t	tcpi_fackets;

	/* Times. */
	uint32_t	tcpi_last_data_sent;
	uint32_t	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	uint32_t	tcpi_last_data_recv;
	uint32_t	tcpi_last_ack_recv;

	/* Metrics. */
	uint32_t	tcpi_pmtu;
	uint32_t	tcpi_rcv_ssthresh;
	uint32_t	tcpi_rtt;
	uint32_t	tcpi_rttvar;
	uint32_t	tcpi_snd_ssthresh;
	uint32_t	tcpi_snd_cwnd;
	uint32_t	tcpi_advmss;
	uint32_t	tcpi_reordering;

	uint32_t	tcpi_rcv_rtt;
	uint32_t	tcpi_rcv_space;

	uint32_t	tcpi_total_retrans;

	uint64_t	tcpi_pacing_rate;
	uint64_t	tcpi_max_pacing_rate;
	uint64_t	tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	uint64_t	tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	uint32_t	tcpi_segs_out;	     /* RFC4898 tcpEStatsPerfSegsOut */
	uint32_t	tcpi_segs_in;	     /* RFC4898 tcpEStatsPerfSegsIn */

	uint32_t	tcpi_notsent_bytes;
	uint32_t	tcpi_min_rtt;
	uint32_t	tcpi_data_segs_in;	/* RFC4898 tcpEStatsDataSegsIn */
	uint32_t	tcpi_data_segs_out;	/* RFC4898 tcpEStatsDataSegsOut */

	uint64_t   tcpi_delivery_rate;

	uint64_t	tcpi_busy_time;      /* Time (usec) busy sending data */
	uint64_t	tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
	uint64_t	tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

	uint32_t	tcpi_delivered;
	uint32_t	tcpi_delivered_ce;

	uint64_t	tcpi_bytes_sent;     /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	uint64_t	tcpi_bytes_retrans;  /* RFC4898 tcpEStatsPerfOctetsRetrans */
	uint32_t	tcpi_dsack_dups;     /* RFC4898 tcpEStatsStackDSACKDups */
	uint32_t	tcpi_reord_seen;     /* reordering events seen */

	uint32_t	tcpi_rcv_ooopack;    /* Out-of-order packets received */

	uint32_t	tcpi_snd_wnd;	     /* peer's advertised receive window after
				      * scaling (bytes)
				      */
	uint32_t	tcpi_rcv_wnd;	     /* local advertised receive window after
				      * scaling (bytes)
				      */

	uint32_t   tcpi_rehash;         /* PLB or timeout triggered rehash attempts */

	uint16_t	tcpi_total_rto;	/* Total number of RTO timeouts, including
				 * SYN/SYN-ACK and recurring timeouts.
				 */
	uint16_t	tcpi_total_rto_recoveries;	/* Total number of RTO
						 * recoveries, including any
						 * unfinished recovery.
						 */
	uint32_t	tcpi_total_rto_time;	/* Total time spent in RTO recoveries
					 * in milliseconds, including any
					 * unfinished recovery.
					 */
} tcp_info_t;

typedef struct
{
    //const struct tcp_info *tcp_info;
    tcp_info_t *tcp_info;
    int tcp_info_len;
    syn_packet_t *saved_syn;
    apr_time_t accept_ts;
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
        if (strcEQ(var, "FINGERPRINT_TCP_MINRTT"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_min_rtt);
        if (strcEQ(var, "FINGERPRINT_TCP_RCVRTT"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_rcv_rtt);
        if (strcEQ(var, "FINGERPRINT_TCP_SNDWND"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_snd_wnd);
        if (strcEQ(var, "FINGERPRINT_TCP_RCVWND"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_rcv_wnd);
        if (strcEQ(var, "FINGERPRINT_TCP_LASTDATARECV"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_last_data_recv * 1000000 / sysconf(_SC_CLK_TCK)); 
        if (strcEQ(var, "FINGERPRINT_TCP_LASTACKRECV"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_last_ack_recv * 1000000 / sysconf(_SC_CLK_TCK));
        if (strcEQ(var, "FINGERPRINT_TCP_SNDMSS"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_snd_mss);
        if (strcEQ(var, "FINGERPRINT_TCP_RCVMSS"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_rcv_mss);
        if (strcEQ(var, "FINGERPRINT_TCP_ADVMSS"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_advmss);
        if (strcEQ(var, "FINGERPRINT_TCP_PMTU"))
            return (char *)apr_psprintf(r->pool, "%lu", (unsigned long) data->tcp_info->tcpi_pmtu);
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

    if (strcEQ(var, "FINGERPRINT_TCP_INFO"))
        return fingerprint_var_tcpinfo(data, r, var);
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
    if (strcEQ(var, "FINGERPRINT_TCP_MINRTT"))
        return fingerprint_var_tcpinfo(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_RCVRTT"))
        return fingerprint_var_tcpinfo(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_SNDWND"))
        return fingerprint_var_tcpinfo(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_RCVWND"))
        return fingerprint_var_tcpinfo(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_LASTDATARECV"))
        return fingerprint_var_tcpinfo(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_LASTACKRECV"))
        return fingerprint_var_tcpinfo(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_SNDMSS"))
        return fingerprint_var_tcpinfo(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_RCVMSS"))
        return fingerprint_var_tcpinfo(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_ADVMSS"))
        return fingerprint_var_tcpinfo(data, r, var);
    if (strcEQ(var, "FINGERPRINT_TCP_PMTU"))
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
    if (strcEQ(var, "FINGERPRINT_ACCEPT_TIME"))
    {
        return apr_psprintf(r->pool, "%" APR_INT64_T_FMT, data->accept_ts);
    }
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
        //else
        //{
        //    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "set TCP_SAVE_SYN on listener for port: %i", (int) lr->bind_addr->port);
        //}   
    }
}


static conn_rec *fingerprint_create_connection(apr_pool_t *p, server_rec *server,
                                     apr_socket_t *csd, long conn_id,
                                     void *sbh, apr_bucket_alloc_t *alloc)
{
    conn_rec *c = NULL;
    
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "create_connection callback");
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "%ld", conn_id);
    return c;
}


static int fingerprint_pre_connection(conn_rec *c, void *csd)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->base_server, "pre_connection callback");
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->base_server, "%ld", c->id);

    fingerprint_conn_data_t *data = NULL;
    //struct tcp_info ti;
    tcp_info_t ti;
    int ti_length = 0;
    int res = 0;
    apr_status_t stat = 0;
    int sd = 0;
    int nonblock = 0;
    char syn_packet[196];
    int syn_length = 96;
    
    
    apr_os_sock_get(&sd, csd);

    //only add fingerprint into to master connection, if this is a slave connection, do nothing.
    if (!c->master)
    {
        data = apr_pcalloc(c->pool, sizeof(*data));
        ap_set_module_config(c->conn_config, &tcpfingerprint_module, data);

        data->accept_ts = apr_time_now();

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


        res = getsockopt(sd, IPPROTO_TCP, TCP_INFO, &ti, (socklen_t *)&ti_length);
        if (res < 0)
        {
            stat = apr_get_netos_error();
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, stat, c, "error getting TCP_INFO");

        } else
        {
            //check ti len?
            data->tcp_info = apr_pmemdup(c->pool, &ti, ti_length);
            data->tcp_info_len = ti_length;
        }

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

    if (dir_conf->export_tcpinfo)
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
    //ap_hook_handler(tcpfingerprint_handler, NULL, NULL, APR_HOOK_MIDDLE);

    //static const char * const pre[] = { "core.c", NULL };
    ap_hook_create_connection(fingerprint_create_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(fingerprint_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(fingerprint_post_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_pre_connection(fingerprint_pre_connection, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(fingerprint_fixups, NULL, NULL, APR_HOOK_FIRST);
}


static const char *enable_envvars(cmd_parms *cmd, void *config, int flag)
{
    fingerprint_dir_conf_t *dir_conf = (fingerprint_dir_conf_t *)config;
    if (flag)
    {
        dir_conf->export_envvars = 1;
    }
    dir_conf->export_envvars_set = 1;   

    return NULL;
}

static const char *enable_envtcpinfo(cmd_parms *cmd, void *config, int flag)
{
    fingerprint_dir_conf_t *dir_conf = (fingerprint_dir_conf_t *)config;
    if (flag)
    {
        dir_conf->export_tcpinfo = 1;
    }
    dir_conf->export_tcpinfo_set = 1;
    return NULL;
}

static const char *enable_envsavedsyn(cmd_parms *cmd, void *config, int flag)
{
    fingerprint_dir_conf_t *dir_conf = (fingerprint_dir_conf_t *)config;
    if (flag)
    {
        dir_conf->export_savedsyn = 1;
    }
    dir_conf->export_savedsyn_set = 1;
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
    fingerprint_dir_conf_t *base = (fingerprint_dir_conf_t *) BASE ; /* This is what was set in the parent context */
    fingerprint_dir_conf_t *add = (fingerprint_dir_conf_t *) ADD ;   /* This is what is set in the new context */
    fingerprint_dir_conf_t *conf = (fingerprint_dir_conf_t *) create_dir_conf(pool, "Merged configuration"); /* This will be the merged configuration */
    fingerprint_dir_conf_t *src = NULL; //switch between base or add based on which has values set

    //always inheret new configuration value if set
    src = (add->export_envvars_set) ? add : base;
    conf->export_envvars = src->export_envvars;
    conf->export_envvars = src->export_envvars_set;
    src = (add->export_savedsyn_set) ? add : base;
    conf->export_savedsyn = src->export_savedsyn;
    conf->export_savedsyn = src->export_savedsyn_set;
    src = (add->export_tcpinfo_set) ? add : base;
    conf->export_tcpinfo = src->export_tcpinfo;
    conf->export_tcpinfo_set = src->export_tcpinfo_set;
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
    { NULL }
};


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA tcpfingerprint_module = {
    STANDARD20_MODULE_STUFF, 
    create_dir_conf,                    /* create per-dir    config structures */
    merge_dir_conf,                     /* merge  per-dir    config structures */
    NULL,                               /* create per-server config structures */
    NULL,                               /* merge  per-server config structures */
    tcpfingerprint_cmds,                /* table of config file commands       */
    tcpfingerprint_register_hooks       /* register hooks                      */
};


