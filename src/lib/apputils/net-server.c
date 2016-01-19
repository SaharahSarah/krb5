/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/apputils/net-server.c - Network code for krb5 servers (kdc, kadmind) */
/*
 * Copyright 1990,2000,2007,2008,2009,2010,2016 by the Massachusetts Institute of Technology.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"
#include "adm_proto.h"
#include <sys/ioctl.h>
#include <syslog.h>

#include <stddef.h>
#include <string.h>
#include "port-sockets.h"
#include "socket-utils.h"

#include <gssrpc/rpc.h>

#ifdef HAVE_NETINET_IN_H
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
/* for SIOCGIFCONF, etc. */
#include <sys/sockio.h>
#endif
#include <sys/time.h>
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <arpa/inet.h>

#ifndef ARPHRD_ETHER /* OpenBSD breaks on multiple inclusions */
#include <net/if.h>
#endif

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>          /* FIONBIO */
#endif

#include "fake-addrinfo.h"
#include "net-server.h"
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>

/* XXX */
#define KDC5_NONET                               (-1779992062L)

#if defined(CMSG_SPACE) && defined(HAVE_STRUCT_CMSGHDR) &&      \
    (defined(IP_PKTINFO) || defined(IPV6_PKTINFO))
#define HAVE_PKTINFO_SUPPORT
#endif

#if defined(HAVE_PKTINFO_SUPPORT) && defined(IP_PKTINFO) && \
    defined(IPV6_PKTINFO)
#define HAVE_FULL_PKTINFO_SUPPORT
#endif

#ifdef HAVE_PKTINFO_SUPPORT
#define CHECK_PKTINFO_SUPPORT 1
#else
#define CHECK_PKTINFO_SUPPORT 0
#endif

#if defined(IP_PKTINFO) && defined(HAVE_STRUCT_IN_PKTINFO)
#define CHECK_IP_PKTINFO 1
#else
#define CHECK_IP_PKTINFO 0
#endif

#if defined(IPV6_PKTINFO) && defined(HAVE_STRUCT_IN6_PKTINFO)
#define CHECK_IPV6_PKTINFO 1
#else
#define CHECK_IPV6_PKTINFO 0
#endif

/**
 * The maximum connections that can be accepted when a socket is set to listen.
 */
#define MAX_CONNECTIONS 5

static int tcp_or_rpc_data_counter;
static int max_tcp_or_rpc_data_connections = 45;

static int
setreuseaddr(int sock, int value)
{
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
}

#if defined(IPV6_V6ONLY)
static int
setv6only(int sock, int value)
{
    return setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value));
}
#endif

/* Use RFC 3542 API below, but fall back from IPV6_RECVPKTINFO to
   IPV6_PKTINFO for RFC 2292 implementations.  */
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif
/* Parallel, though not standardized.  */
#ifndef IP_RECVPKTINFO
#define IP_RECVPKTINFO IP_PKTINFO
#endif

#ifdef HAVE_PKTINFO_SUPPORT
static int
set_pktinfo(int sock, int family)
{
    int sockopt = 1;
    int option = 0, proto = 0;

    if (family == 0)
        return EINVAL;

    switch (family) {
    case AF_INET * CHECK_IP_PKTINFO:
        proto = IPPROTO_IP;
        option = IP_RECVPKTINFO;
        break;
    case AF_INET6 * CHECK_IPV6_PKTINFO:
        proto = IPPROTO_IPV6;
        option = IPV6_RECVPKTINFO;
        break;
    default:
        return EINVAL;
    }
    if (setsockopt(sock, proto, option, &sockopt, sizeof(sockopt)))
        return errno;
    return 0;
}
#endif

static const char *
paddr(struct sockaddr *sa)
{
    static char buf[100];
    char portbuf[10];
    if (getnameinfo(sa, sa_socklen(sa),
                    buf, sizeof(buf), portbuf, sizeof(portbuf),
                    NI_NUMERICHOST|NI_NUMERICSERV))
        strlcpy(buf, "<unprintable>", sizeof(buf));
    else {
        unsigned int len = sizeof(buf) - strlen(buf);
        char *p = buf + strlen(buf);
        if (len > 2+strlen(portbuf)) {
            *p++ = '.';
            len--;
            strncpy(p, portbuf, len);
        }
    }
    return buf;
}

/* KDC data.  */

enum conn_type {
    CONN_UDP, CONN_UDP_PKTINFO, CONN_TCP_LISTENER, CONN_TCP,
    CONN_RPC_LISTENER, CONN_RPC,
    CONN_ROUTING
};

enum bind_type {
    udp, tcp, rpc
};

static const char * const BIND_TYPE_NAMES[] =
{
    [udp] = "UDP",
    [tcp] = "TCP",
    [rpc] = "RPC",
};

/* Per-connection info.  */
struct connection {
    void *handle;
    const char *prog;
    enum conn_type type;

    /* Connection fields (TCP or RPC) */
    struct sockaddr_storage addr_s;
    socklen_t addrlen;
    char addrbuf[56];
    krb5_fulladdr faddr;
    krb5_address kaddr;

    /* Incoming data (TCP) */
    size_t bufsiz;
    size_t offset;
    char *buffer;
    size_t msglen;

    /* Outgoing data (TCP) */
    krb5_data *response;
    unsigned char lenbuf[4];
    sg_buf sgbuf[2];
    sg_buf *sgp;
    int sgnum;

    /* Crude denial-of-service avoidance support (TCP or RPC) */
    time_t start_time;

    /* RPC-specific fields */
    SVCXPRT *transp;
    int rpc_force_close;
};


#define SET(TYPE) struct { TYPE *data; size_t n, max; }

/* Start at the top and work down -- this should allow for deletions
   without disrupting the iteration, since we delete by overwriting
   the element to be removed with the last element.  */
#define FOREACH_ELT(set,idx,vvar)                                       \
    for (idx = set.n-1; idx >= 0 && (vvar = set.data[idx], 1); idx--)

#define GROW_SET(set, incr, tmpptr)                                     \
    ((set.max + incr < set.max                                          \
      || ((set.max + incr) * sizeof(set.data[0]) / sizeof(set.data[0])  \
          != set.max + incr))                                           \
     ? 0                         /* overflow */                         \
     : ((tmpptr = realloc(set.data,                                     \
                          (set.max + incr) * sizeof(set.data[0])))      \
        ? (set.data = tmpptr, set.max += incr, 1)                       \
        : 0))

/* 1 = success, 0 = failure */
#define ADD(set, val, tmpptr)                           \
    ((set.n < set.max || GROW_SET(set, 10, tmpptr))     \
     ? (set.data[set.n++] = val, 1)                     \
     : 0)

#define DEL(set, idx)                           \
    (set.data[idx] = set.data[--set.n], 0)

#define FREE_SET_DATA(set)                                      \
    (free(set.data), set.data = 0, set.max = 0, set.n = 0)

/*
 * N.B.: The Emacs cc-mode indentation code seems to get confused if
 * the macro argument here is one word only.  So use "unsigned short"
 * instead of the "u_short" we were using before.
 */
struct rpc_svc_data {
    u_long prognum;
    u_long versnum;
    void (*dispatch)();
};

struct bind_address {
    char *address;
    u_short port;
    enum bind_type type;
    struct rpc_svc_data rpc_svc_data;
};

static SET(verto_ev *) events;
static SET(struct bind_address) bind_addresses;

verto_ctx *
loop_init(verto_ev_type types)
{
    types |= VERTO_EV_TYPE_IO;
    types |= VERTO_EV_TYPE_SIGNAL;
    types |= VERTO_EV_TYPE_TIMEOUT;
    return verto_default(NULL, types);
}

static void
do_break(verto_ctx *ctx, verto_ev *ev)
{
    krb5_klog_syslog(LOG_DEBUG, _("Got signal to request exit"));
    verto_break(ctx);
}

struct sighup_context {
    void *handle;
    void (*reset)(void *);
};

static void
do_reset(verto_ctx *ctx, verto_ev *ev)
{
    struct sighup_context *sc = (struct sighup_context*) verto_get_private(ev);

    krb5_klog_syslog(LOG_DEBUG, _("Got signal to reset"));
    krb5_klog_reopen(get_context(sc->handle));
    if (sc->reset)
        sc->reset(sc->handle);
}

static void
free_sighup_context(verto_ctx *ctx, verto_ev *ev)
{
    free(verto_get_private(ev));
}

krb5_error_code
loop_setup_signals(verto_ctx *ctx, void *handle, void (*reset)())
{
    struct sighup_context *sc;
    verto_ev *ev;

    if (!verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, do_break, SIGINT)  ||
        !verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, do_break, SIGTERM) ||
        !verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, do_break, SIGQUIT) ||
        !verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, VERTO_SIG_IGN, SIGPIPE))
        return ENOMEM;

    ev = verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, do_reset, SIGHUP);
    if (!ev)
        return ENOMEM;

    sc = malloc(sizeof(*sc));
    if (!sc)
        return ENOMEM;

    sc->handle = handle;
    sc->reset = reset;
    verto_set_private(ev, sc, free_sighup_context);
    return 0;
}

/*
 * Add a bind address to the loop.
 *
 * Arguments:
 * - address
 *      A string for the address. Pass NULL to use the wildcard address (binds
 *      to all interfaces). An optional port number, separated from the address
 *      by a colon, may be included.  If the name or address contains colons
 *      (for example, if it is an IPv6 address), enclose it in square brackets
 *      to distinguish the colon from a port separator.
 *      NOTE: Currently getaddrinfo is used with no restrictions, so in theory
 *      a hostname could work. Whether or not to allow that feature is up to
 *      the implementer.
 * - port
 *      What port the socket should be set to.
 * - type
 *      bind_type for the socket.
 * - rpc_data
 *      An optional rpc_svc_data containing the rpc data needed for an rpc
 *      connection. Required when type is rpc, otherwise should be NULL, but
 *      the value is ignored.
 *
 * returns 0 on success, otherwise an error code.
 *
 */
static krb5_error_code
loop_add_address(/* NULL */ const char *address,
                            int port,
                            enum bind_type type,
                 /* NULL */ struct rpc_svc_data *rpc_data)
{
    int     i;
    void   *tmp;
    struct bind_address addr, val;
    char   *p_addr = NULL;
    krb5_error_code ret;

    /* Make sure that if this is an rpc address that the rpc_data is valid. */
    if (type == rpc && rpc_data == NULL) {
        ret = EINVAL;
        krb5_klog_syslog(LOG_ERR, "rpc_svc_data required for rpc addresses");
        goto cleanup;
    }

    /* Check for conflicting addresses. */
    FOREACH_ELT(bind_addresses, i, val) {
        if (type == val.type && port == val.port) {
            /* If a wildcard address is being added make sure to remove any
             * direct addresses. */
            if (!address && val.address) {
                krb5_klog_syslog(LOG_DEBUG,
                                 _("Removing address %s since wildcard address"
                                 " is being added"),
                                 val.address);
                free(val.address);
                DEL(bind_addresses, i);
                continue;
            } else if (!(address || val.address) /* Both are wildcard (NULL) */
                       || !strcmp(address, val.address)) {
                krb5_klog_syslog(LOG_DEBUG,
                                 _("Address already added to server"));
                ret = 0;
                goto cleanup;
            }
        }
    }

    /* Copy the address if it is specified */
    if (address != NULL) {
        p_addr = strdup(address);
        if (p_addr == NULL) {
            ret = ENOMEM;
            goto cleanup;
        }
    }

    /* Clear addr and set the values */
    memset(&addr, 0, sizeof(addr));
    addr.address = p_addr;
    addr.port = port;
    /* Make sure a valid port number was passed. */
    if (addr.port != port) {
        ret = EINVAL;
        krb5_klog_syslog(LOG_ERR, _("Invalid port %d"), port);
        goto cleanup;
    }
    addr.type = type;
    if (rpc_data != NULL)
        memcpy(&addr.rpc_svc_data, rpc_data, sizeof(addr.rpc_svc_data));

    /* Add the address to the set. */
    if (!ADD(bind_addresses, addr, tmp)) {
        ret = ENOMEM;
        goto cleanup;
    }

    p_addr = NULL;
    ret = 0;

  cleanup:
    free(p_addr);
    return ret;
}

/*
 * Add bind addresses to the loop.
 *
 * Arguments:
 *
 * - addresses
 *      A string for the addresses. Pass NULL to use the wildcard address
 *      (binds to all interfaces). Supported delimeters can be found in
 *      ADDRESSES_DELIM.
 *      NOTE: Currently getaddrinfo is used with no restrictions, so in theory
 *      a hostname could work. Whether or not to allow that feature is up to
 *      the implementer.
 * - default_port
 *      What port the socket should be set to if not specified in addresses.
 * - type
 *      bind_type for the socket.
 * - rpc_data
 *      An optional rpc_svc_data containing the rpc data needed for an rpc
 *      connection. Required when type is rpc, otherwise should be NULL, but
 *      the value is ignored.
 */
static krb5_error_code
loop_add_addresses(/* NULL */ const char *addresses,
                   int default_port,
                   enum bind_type type,
                   /* NULL */ struct rpc_svc_data *rpc_data)
{
    krb5_error_code ret;
    char *addresses_copy = NULL;
    char *host = NULL;
    char *next;
    int h_port;

    /* If no addresses are set bind to the wildcard address. */
    if (addresses == NULL) {
        ret = loop_add_address(NULL, default_port, type, rpc_data);
        goto cleanup;
    }

    /*
     * We need to copy the addresses string because strtok modifies the string
     * that it's tokenizing.
     */
    addresses_copy = strdup(addresses);
    if (addresses_copy == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }

    /*
     * Start tokenizing the addresses string. If NULL is returned then the
     * string contained no addresses, so bind to the wildcard address.
     */
    next = strtok(addresses_copy, ADDRESSES_DELIM);
    if (next == NULL) {
        ret = loop_add_address(NULL, default_port, type, rpc_data);
        goto cleanup;
    }

    /* Loop through each address and add it to the loop. */
    for (; next != NULL; next = strtok(NULL, ADDRESSES_DELIM)) {
        /* Parse the host string. */
        ret = k5_parse_host_string(next, default_port, &host, &h_port);
        if (ret != 0)
            goto cleanup;

        ret = loop_add_address(host, h_port, type, rpc_data);
        if (ret != 0)
            goto cleanup;

        free(host);
        host = NULL;
    }

    ret = 0;

cleanup:
    free(addresses_copy);
    free(host);
    return ret;
}

krb5_error_code
loop_add_udp_address(int default_port, /* NULL */ const char *addresses)
{
    return loop_add_addresses(addresses, default_port, udp, NULL);
}

krb5_error_code
loop_add_tcp_address(int default_port, /* NULL */ const char *addresses)
{
    return loop_add_addresses(addresses, default_port, tcp, NULL);
}

krb5_error_code
loop_add_rpc_service(int default_port, /* NULL */ const char *addresses,
                     u_long prognum, u_long versnum, void (*dispatchfn)())
{
    /* Set the rpc_svc_data values */
    struct rpc_svc_data svc;
    svc.prognum = prognum;
    svc.versnum = versnum;
    svc.dispatch = dispatchfn;

    return loop_add_addresses(addresses, default_port, rpc, &svc);
}


#define USE_AF AF_INET
#define USE_TYPE SOCK_DGRAM
#define USE_PROTO 0
#define SOCKET_ERRNO errno
#include "foreachaddr.h"

struct socksetup {
    verto_ctx *ctx;
    void *handle;
    const char *prog;
    krb5_error_code retval;
};

static void
free_connection(struct connection *conn)
{
    if (!conn)
        return;
    if (conn->response)
        krb5_free_data(get_context(conn->handle), conn->response);
    if (conn->buffer)
        free(conn->buffer);
    if (conn->type == CONN_RPC_LISTENER && conn->transp != NULL)
        svc_destroy(conn->transp);
    free(conn);
}

static void
remove_event_from_set(verto_ev *ev)
{
    verto_ev *tmp;
    int i;

    /* Remove the event from the events. */
    FOREACH_ELT(events, i, tmp)
        if (tmp == ev) {
            DEL(events, i);
            break;
        }
}

static void
free_socket(verto_ctx *ctx, verto_ev *ev)
{
    struct connection *conn = NULL;
    fd_set fds;
    int fd;

    remove_event_from_set(ev);

    fd = verto_get_fd(ev);
    conn = verto_get_private(ev);

    /* Close the file descriptor. */
    krb5_klog_syslog(LOG_INFO, _("closing down fd %d"), fd);
    if (fd >= 0 && (!conn || conn->type != CONN_RPC || conn->rpc_force_close))
        close(fd);

    /* Free the connection struct. */
    if (conn) {
        switch (conn->type) {
        case CONN_RPC:
            if (conn->rpc_force_close) {
                FD_ZERO(&fds);
                FD_SET(fd, &fds);
                svc_getreqset(&fds);
                if (FD_ISSET(fd, &svc_fdset)) {
                    krb5_klog_syslog(LOG_ERR,
                                     _("descriptor %d closed but still "
                                       "in svc_fdset"),
                                     fd);
                }
            }
            /* Fall through. */
        case CONN_TCP:
            tcp_or_rpc_data_counter--;
            break;
        default:
            break;
        }

        free_connection(conn);
    }
}

static verto_ev *
make_event(verto_ctx *ctx, verto_ev_flag flags, verto_callback callback,
           int sock, struct connection *conn, int addevent)
{
    verto_ev *ev;
    void *tmp;

    ev = verto_add_io(ctx, flags, callback, sock);
    if (!ev) {
        com_err(conn->prog, ENOMEM, _("cannot create io event"));
        return NULL;
    }

    if (addevent) {
        if (!ADD(events, ev, tmp)) {
            com_err(conn->prog, ENOMEM, _("cannot save event"));
            verto_del(ev);
            return NULL;
        }
    }

    verto_set_private(ev, conn, free_socket);
    return ev;
}

static verto_ev *
add_fd(struct socksetup *data, int sock, enum conn_type conntype,
       verto_ev_flag flags, verto_callback callback, int addevent)
{
    struct connection *newconn;

#ifndef _WIN32
    if (sock >= FD_SETSIZE) {
        data->retval = EMFILE;  /* XXX */
        com_err(data->prog, 0,
                _("file descriptor number %d too high"), sock);
        return NULL;
    }
#endif
    newconn = malloc(sizeof(*newconn));
    if (newconn == NULL) {
        data->retval = ENOMEM;
        com_err(data->prog, ENOMEM,
                _("cannot allocate storage for connection info"));
        return NULL;
    }
    memset(newconn, 0, sizeof(*newconn));
    newconn->handle = data->handle;
    newconn->prog = data->prog;
    newconn->type = conntype;

    return make_event(data->ctx, flags, callback, sock, newconn, addevent);
}

static void process_packet(verto_ctx *ctx, verto_ev *ev);
static void accept_tcp_connection(verto_ctx *ctx, verto_ev *ev);
static void process_tcp_connection_read(verto_ctx *ctx, verto_ev *ev);
static void process_tcp_connection_write(verto_ctx *ctx, verto_ev *ev);
static void accept_rpc_connection(verto_ctx *ctx, verto_ev *ev);
static void process_rpc_connection(verto_ctx *ctx, verto_ev *ev);

static verto_ev *
add_tcp_read_fd(struct socksetup *data, int sock)
{
    return add_fd(data, sock, CONN_TCP,
                  VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_PERSIST,
                  process_tcp_connection_read, 1);
}

/*
 * Create a socket and bind it to addr.  Ensure the socket will work with
 * select().  Set the socket cloexec, reuseaddr, and if applicable v6-only.
 * Does not call listen().  Returns -1 on failure after logging an error.
 */
static int
create_server_socket (struct socksetup *data, struct sockaddr *addr, int type)
{
    int sock = -1, ret = -1;

    sock = socket(addr->sa_family, type, 0);
    if (sock == -1) {
        ret = -1;
        data->retval = errno;
        com_err(data->prog, errno, _("Cannot create TCP server socket on %s"),
                  paddr(addr));
        goto cleanup;
    }

#ifndef _WIN32                  /* Windows FD_SETSIZE is a count. */
    if (sock >= FD_SETSIZE) {
        ret = -1;
        data->retval = EBADF;
        com_err(data->prog, 0, _("TCP socket fd number %d (for %s) too high"),
                sock, paddr(addr));
        goto cleanup;
    }
#endif

    if (setreuseaddr(sock, 1) < 0) {
        com_err(data->prog, errno,
                _("Cannot enable SO_REUSEADDR on fd %d"), sock);
    }

    if (addr->sa_family == AF_INET6) {
#ifdef IPV6_V6ONLY
        if (setv6only(sock, 1))
            com_err(data->prog, errno,
                    _("setsockopt(%d,IPV6_V6ONLY,1) failed"), sock);
        else
            com_err(data->prog, 0, _("setsockopt(%d,IPV6_V6ONLY,1) worked"),
                    sock);
#else
        krb5_klog_syslog(LOG_INFO, _("no IPV6_V6ONLY socket option support"));
#endif /* IPV6_V6ONLY */
    }

    if (bind(sock, addr, sa_socklen(addr)) == -1) {
        ret = -1;
        data->retval = errno;
        com_err(data->prog, errno, _("Cannot bind server socket on %s"),
                paddr(addr));
        goto cleanup;
    }

    ret = sock;
    sock = -1;

cleanup:
    if (sock >= 0)
        close(sock);
    return ret;
}

static verto_ev *
add_rpc_data_fd(struct socksetup *data, int sock)
{
    return add_fd(data, sock, CONN_RPC,
                  VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_PERSIST,
                  process_rpc_connection, 1);
}

static const int one = 1;

/* Set the non-blocking io option on a socket.*/
static int
setnbio(int sock)
{
    krb5_klog_syslog(LOG_DEBUG, _("Setting nbio on socket"));
    return ioctlsocket(sock, FIONBIO, (const void *)&one);
}

/* Set the keepalive option on a socket. */
static int
setkeepalive(int sock)
{
    return setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
}

/* Turn off the linger option on a socket. */
static int
setnolinger(int sock)
{
    static const struct linger ling = { 0, 0 };
    krb5_klog_syslog(LOG_DEBUG, _("Turning off linger on socket"));
    return setsockopt(sock, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
}

#ifdef HAVE_PKTINFO_SUPPORT
union pktinfo {
#ifdef HAVE_STRUCT_IN6_PKTINFO
    struct in6_pktinfo pi6;
#endif
#ifdef HAVE_STRUCT_IN_PKTINFO
    struct in_pktinfo pi4;
#endif
    char c;
};
#endif

#ifdef HAVE_STRUCT_RT_MSGHDR
#include <net/route.h>

static void
do_network_reconfig(verto_ctx *ctx, verto_ev *ev)
{
    struct connection *conn = verto_get_private(ev);
    if (loop_setup_network(ctx, conn->handle, conn->prog) != 0) {
        krb5_klog_syslog(LOG_ERR, _("Failed to reconfigure network, exiting"));
        verto_break(ctx);
    }
}

static int
routing_update_needed(struct rt_msghdr *rtm)
{
    switch (rtm->rtm_type) {
    case RTM_ADD:
    case RTM_DELETE:
    case RTM_NEWADDR:
    case RTM_DELADDR:
    case RTM_IFINFO:
#ifdef RTM_OLDADD
    case RTM_OLDADD:
#endif
#ifdef RTM_OLDDEL
    case RTM_OLDDEL:
#endif
        /*
         * Some flags indicate routing table updates that don't
         * indicate local address changes.  They may come from
         * redirects, or ARP, etc.
         *
         * This set of symbols is just an initial guess based on
         * some messages observed in real life; working out which
         * other flags also indicate messages we should ignore,
         * and which flags are portable to all system and thus
         * don't need to be conditionalized, is left as a future
         * exercise.
         */
#ifdef RTF_DYNAMIC
        if (rtm->rtm_flags & RTF_DYNAMIC)
            break;
#endif
#ifdef RTF_CLONED
        if (rtm->rtm_flags & RTF_CLONED)
            break;
#endif
#ifdef RTF_LLINFO
        if (rtm->rtm_flags & RTF_LLINFO)
            break;
#endif
        return 1;
    case RTM_RESOLVE:
#ifdef RTM_NEWMADDR
    case RTM_NEWMADDR:
    case RTM_DELMADDR:
#endif
    case RTM_MISS:
    case RTM_REDIRECT:
    case RTM_LOSING:
    case RTM_GET:
        /* Not interesting.  */
#if 0
        krb5_klog_syslog(LOG_DEBUG, "routing msg not interesting");
#endif
        break;
    default:
        krb5_klog_syslog(LOG_INFO,
                         _("unhandled routing message type %d, "
                           "will reconfigure just for the fun of it"),
                         rtm->rtm_type);
        return 1;
    }

    return 0;
}

static void
process_routing_update(verto_ctx *ctx, verto_ev *ev)
{
    int fd;
    ssize_t n_read;
    size_t sz_read;
    struct rt_msghdr rtm;
    struct connection *conn;

    fd = verto_get_fd(ev);
    conn = verto_get_private(ev);
    while ((n_read = read(fd, &rtm, sizeof(rtm))) > 0) {
        sz_read = (size_t) n_read; /* Safe, since we just checked the sign */
        if (sz_read < sizeof(rtm)) {
            /* Quick hack to figure out if the interesting
               fields are present in a short read.

               A short read seems to be normal for some message types.
               Only complain if we don't have the critical initial
               header fields.  */
#define RS(FIELD) (offsetof(struct rt_msghdr, FIELD) + sizeof(rtm.FIELD))
            if (sz_read < RS(rtm_type) ||
                sz_read < RS(rtm_version) ||
                sz_read < RS(rtm_msglen)) {
                krb5_klog_syslog(LOG_ERR,
                                 _("short read (%d/%d) from routing socket"),
                                 (int)sz_read, (int) sizeof(rtm));
                return;
            }
        }
        if (rtm.rtm_msglen > sizeof(rtm)) {
            /* It appears we get a partial message and the rest is
               thrown away?  */
        } else if (rtm.rtm_msglen != sz_read) {
            krb5_klog_syslog(LOG_ERR,
                             _("read %d from routing socket but msglen is %d"),
                             (int)sz_read, rtm.rtm_msglen);
        }

        if (routing_update_needed(&rtm)) {
            /* Ideally we would use idle here instead of timeout. However, idle
             * is not universally supported yet in all backends. So let's just
             * use timeout for now to avoid locking into a loop. */
            ev = verto_add_timeout(ctx, VERTO_EV_FLAG_NONE,
                                   do_network_reconfig, 0);
            verto_set_private(ev, conn, NULL);
            assert(ev);
        }
    }
}
#endif

krb5_error_code
loop_setup_routing_socket(verto_ctx *ctx, void *handle, const char *progname)
{
#ifdef HAVE_STRUCT_RT_MSGHDR
    struct socksetup data;
    int sock;

    data.ctx = ctx;
    data.handle = handle;
    data.prog = progname;
    data.retval = 0;

    sock = socket(PF_ROUTE, SOCK_RAW, 0);
    if (sock < 0) {
        int e = errno;
        krb5_klog_syslog(LOG_INFO, _("couldn't set up routing socket: %s"),
                         strerror(e));
    } else {
        krb5_klog_syslog(LOG_INFO, _("routing socket is fd %d"), sock);
        setnbio(sock);
        add_fd(&data, sock, CONN_ROUTING,
               VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_PERSIST,
               process_routing_update, 0);
    }
#endif
    return 0;
}

/* Callback for when the file descriptor is added to the verto event loop. */
typedef krb5_error_code (*on_fd_added) (struct socksetup *data,
                                  struct bind_address *ba, int sock,
                                  verto_ev *ev);

/**
 * An enum containing the flags that can be set for setting up a socket.
 */
enum sock_flag
{
    /**
     * Set the socket to listen for connections.
     */
    LISTEN = 1 << 0,
    /**
     * Set the socket to non-blocking io mode.
     */
    NBIO = 1 << 1,
    /**
     * Turn off the linger socket option.
     */
    NOLINGER = 1 << 2,
    /**
     * Setup pktinfo on the socket.
     */
    PKTINFO = 1 << 3
};

/**
 * An enum map to sock families for each bind_type.
 */
static const int BIND_FAMILIES[] =
{
    [udp] = SOCK_DGRAM,
    [tcp] = SOCK_STREAM,
    [rpc] = SOCK_STREAM
};

/*
 * Setup a socket for the server.
 *
 * Arguments:
 *
 * - ba
 *      The bind address and port for the socket.
 * - ai
 *      The addrinfo struct to use for creating the socket.
 * - flags
 *      The sock_flag options for for setting up this socket.
 * - ctype
 *      The conn_type of this socket.
 * - fdcb
 *      An optional callback for when the socket is added to the verto event
 *      loop. May be NULL.
 */
static  krb5_error_code
setup_socket(struct socksetup *data, struct bind_address *ba,
             struct sockaddr *sock_address, int flags,
             verto_callback vcb, enum conn_type ctype,
             /*@null@ */ on_fd_added fdcb)
{
    int      sock = -1;
    int      ret;
    verto_ev *ev = NULL;


    krb5_klog_syslog(LOG_DEBUG, _("Setting up %s socket for address %s"),
                     BIND_TYPE_NAMES[ba->type], paddr(sock_address));
    /* Create the socket. */
    sock = create_server_socket(data, sock_address, BIND_FAMILIES[ba->type]);
    if (sock == -1) {
        ret = data->retval;
        goto cleanup;
    }

    /* Set the socket to listen for connections if requested. */
    if (flags & LISTEN && listen(sock, MAX_CONNECTIONS) < 0) {
        ret = errno;
        com_err(data->prog, errno,
                _("Cannot listen on %s server socket on %s"),
                BIND_TYPE_NAMES[ba->type], paddr(sock_address));
        goto cleanup;
    }

    /* Set the socket non-blocking io option if requested. */
    if (flags & NBIO && setnbio(sock)) {
        ret = errno;
        com_err(data->prog, errno,
                _("cannot set listening %s socket on %s non-blocking"),
                BIND_TYPE_NAMES[ba->type], paddr(sock_address));
        goto cleanup;
    }

    /* Turn off the linger option if requested. */
    if (flags & NOLINGER && setnolinger(sock)) {
        ret = errno;
        com_err(data->prog, errno,
                _("cannot set SO_LINGER on %s socket on %s"),
                BIND_TYPE_NAMES[ba->type], paddr(sock_address));
        goto cleanup;
    }

#ifdef HAVE_PKTINFO_SUPPORT
    /* Set pktinfo for the socket if requested and supported, or fail if not
     * supported. */
    if (flags & PKTINFO) {
        if (CHECK_PKTINFO_SUPPORT) {
            krb5_klog_syslog(LOG_DEBUG, _("Setting pktinfo on socket %s"),
                         paddr(sock_address));
            ret = set_pktinfo(sock, BIND_FAMILIES[ba->type]);
            if (ret) {
                com_err(data->prog, ret,
                        _("Cannot request packet info for udp socket address "
                          "%s port %d"),
                        paddr(sock_address), ba->port);
                goto cleanup;
            }
        } else {
            /* PKTINFO flag set but no PKTINFO support */
            ret = EINVAL;
            krb5_klog_syslog(LOG_ERR,
                             _("pktinfo requested but not supported"));
            goto cleanup;
        }
    }
#endif

    /* Add the socket to the event loop. */
    ev = add_fd(data, sock, ctype,
                VERTO_EV_FLAG_IO_READ |
                VERTO_EV_FLAG_PERSIST |
                VERTO_EV_FLAG_REINITIABLE, vcb, 1);

    if (ev == NULL) {
        krb5_klog_syslog(LOG_ERR, _("Error attempting to add verto event"));
        ret = data->retval;
        goto cleanup;
    }

    /* Call the on_fd_added callback if one was passed. */
    if (fdcb != NULL) {
        ret = fdcb(data, ba, sock, ev);
        if (ret != 0) {
            krb5_klog_syslog(LOG_ERR,
                             _("Error in verto event callback function"));
            ret = data->retval;
            goto cleanup;
        }
    }

    ev = NULL;
    sock = -1;
    ret = 0;

  cleanup:
    if (sock >= 0)
        close(sock);
    if (ev != NULL)
        verto_del(ev);
    return ret;
}

/* on_fd_added callback function for rpc listener sockets. */
static krb5_error_code
on_rpc_listener_fd_added(struct socksetup *data, struct bind_address *ba,
                         int sock, verto_ev *ev)
{
    struct connection *conn;
    int ret;

    krb5_klog_syslog(LOG_DEBUG,
                     _("RPC added to event loop, setting up rpc service"));
    conn = verto_get_private(ev);
    conn->transp = svctcp_create(sock, 0, 0);
    if (conn->transp == NULL) {
        ret = errno;
        krb5_klog_syslog(LOG_ERR,
                         _("Cannot create RPC service: %s"),
                         strerror(ret));
        return ret;
    }

    if (!svc_register(conn->transp, ba->rpc_svc_data.prognum,
        ba->rpc_svc_data.versnum, ba->rpc_svc_data.dispatch, 0)) {
        ret = errno;
        krb5_klog_syslog(LOG_ERR,
                         _("Cannot register RPC service: %s"),
                         strerror(ret));
        return ret;
    }

    return 0;
}

#ifndef HAVE_FULL_PKTINFO_SUPPORT
/*****************************************************************************
 *   Terrible hack to get around issues of UDP on Unix without Ip PktInfo.   *
 *                          Get rid of me ASAP!                              *
 *****************************************************************************/

/*
 * This struct contains all the arguments that are passed to
 * WORKAROUND_setup_local_addresses. This is necessary because of the design of
 * foreach_localaddr.
 */
struct WORKAROUND_setup_local_address_args {
    struct socksetup *data;
    struct bind_address *ba;
    int sock_family;
    enum sock_flag flags;
    verto_callback *vcb;
    enum conn_type ctype;
    on_fd_added fdcb; /* NULL */
    int num_addresses_added;
};

/*
 * Workaround necessary for machines that lack IP PktInfo support and are
 * listening on a UDP wildcard address. Unix will take the packets in for a
 * UDP socket but is not guaranteed to send the packets out the same address.
 * krb5 requires this functionality, so it needs to bind to every single
 * available interface individually.
 *
 * This follows the function callback prototype necessary for
 * foreach_localaddr.
 *
 * Arguments:
 * - v_args
 *      A void pointer to a WORKAROUND_setup_local_address_args. This
 *      is passed to foreach_localaddr in the data argument.
 * - sock_address
 *      The sock address passsed from  foreach_localaddr which should
 *      have a local interface address.
 *
 * As per the requirements laid out in foreach_localaddr, 0 is returned on
 * success, while an error code is returned otherwise. Since many times a local
 * address could fail, this doesn't actually ever return anything but 0.
 */
static int
WORKAROUND_setup_local_address(void *v_args, struct sockaddr *sock_address)
{
    struct WORKAROUND_setup_local_address_args *args;
    int ret;

    args = (struct WORKAROUND_setup_local_address_args *)v_args;

    /* Check to make sure the sock_address family matches the request family */
    if (sock_address->sa_family == args->sock_family) {
        krb5_klog_syslog(LOG_DEBUG,
                         _("Setting up socket for local address %s."),
                         paddr(sock_address));
        /* Set the port on the sock_address to the requested port */
        sa_setport(sock_address, args->ba->port);

        /* Now setup the socket */
        ret = setup_socket(args->data, args->ba, sock_address, args->flags,
                           args->vcb, args->ctype, args->fdcb);
        if (ret != 0) {
            args->data->retval = ret;
            krb5_klog_syslog(LOG_ERR, _("Error adding local address %s"),
                             paddr(sock_address));
        } else {
            /* Increment the num_addresses_added so that the caller will know
             * how many addresses were successfully bound. */
            args->num_addresses_added++;
        }
    } else {
        krb5_klog_syslog(LOG_DEBUG,
                         _("Skipping local address because it does not "
                           "match requested family"));
    }

    /*
     * Return 0 as some local addresses might fail binding, and all we really
     * need is 1.
     */
    return 0;
}

/*
 * Workaround necessary for machines that lack IP PktInfo support and are
 * listening on a UDP wildcard address. Unix will take the packets in for a
 * UDP socket but is not guaranteed to send the packets out the same address.
 * krb5 requires this functionality, so it needs to bind to every single
 * available interface individually.
 *
 * Arguments:
 *
 * - ba
 *      The bind_address for the requested socket, used for the port number.
 * - sock_family
 *      The socket family to filter the local addresses to bind to.
 * - flags
 *      The sock_flag flags for setting up the socket.
 * - ctype
 *      The conn_type for the socket. It should probably be CONN_UDP,
 *      but I'm not going to tell you what to do.
 * - fdcp
 *      The optional callback to be called once the socket has been added to
 *      verto event loop. May be NULL.
 *
 * returns 0 on success, otherwise an error code. If no addresses were bound
 * this error code will be ENODEV.
 */
static  krb5_error_code
WORKAROUND_setup_local_addresses(struct socksetup *data,
                                 struct bind_address *ba, int sock_family,
                                 enum sock_flag flags, verto_callback * vcb,
                                 enum conn_type ctype,
                                 /* NULL */on_fd_added fdcb)
{
    struct WORKAROUND_setup_local_address_args args;
    int err;

    /* Add the arguments to the argument struct */
    args.data = data;
    args.ba = ba;
    args.sock_family = sock_family;
    args.flags = flags;
    args.vcb = vcb;
    args.ctype = ctype;
    args.fdcb = fdcb;
    /*
     * Keep track of the number of addresses added. If this ends up being 0
     * then nothing was bound. I doubt that the caller would be fine with that.
     */
    args.num_addresses_added = 0;

    /*
     * Loop through all of the local addresses and send the results to
     * WORKAROUND_setup_local_address.
     */
    err = foreach_localaddr(&args, &WORKAROUND_setup_local_address,
                            NULL, NULL);
    if (err != 0) {
        krb5_klog_syslog(LOG_ERR,
                         _("Error encountered trying to add local "
                           "UDP addresses."));
        return data->retval;
    }

    if (args.num_addresses_added == 0) {
        krb5_klog_syslog(LOG_ERR,
                         _("Could not find any local addresses to "
                           "bind for UDP."));
        /*
         * Returning ENODEV in this case. There might be a better error number
         * that I failed to see. If you change this, make sure to update the
         * documentation in the above comment.
         */
        return ENODEV;
    }

    krb5_klog_syslog(LOG_INFO, _("Bound to %d local addresses"),
                     args.num_addresses_added);

    return 0;
}
/*****************************************************************************
 *                         End of terrible hack.                             *
 *****************************************************************************/
#endif /* HAVE_FULL_PKTINFO_SUPPORT */

/*
 * Setup all the socket addresses that the net-server should listen to.
 *
 * This function uses getaddrinfo to figure out all the addresses. This will
 * automatically figure out which socket families that should be used on the
 * host making it useful even for wildcard addresses.
 *
 * Arguments:
 * - data
 *      A pointer to the socksetup data.
 */
static  krb5_error_code
setup_addresses(struct socksetup *data)
{
    /* An bind_type enum map for the verto callback functions. */
    static verto_callback *const VERTO_CALLBACK[] = {
        [udp] = &process_packet,
        [tcp] = &accept_tcp_connection,
        [rpc] = &accept_rpc_connection
    };

    /* An bind_type enum map for the on_fd_added callback functions. */
    static on_fd_added const FD_ADDED_CALLBACK[] = {
        [udp] = NULL,
        [tcp] = NULL,
        [rpc] = &on_rpc_listener_fd_added
    };

    size_t  i;
    int     ret, flags, err;
    struct bind_address val;
    struct addrinfo hints, *result = NULL, *r_next = NULL;
    verto_callback vcb;
    enum conn_type ctype;

    /* Check to make sure addresses were added to the server. You can't
     * really run a net server without the net. */
    if (bind_addresses.n == 0) {
        krb5_klog_syslog(LOG_ERR, _("No addresses added to the net server"));
        ret = EINVAL;
        goto cleanup;
    }

    memset(&hints, 0, sizeof(struct addrinfo));

    /* Setup the hints for getaddrinfo. */

    /* Set the family to AF_UNSPEC to tell getaddrinfo to return both AF_INET
     * and AF_INET6 addresses. */
    hints.ai_family = AF_UNSPEC;
    /*
     * Add the AI_PASSIVE flag so that when the address is NULL that a wildcard
     * address will be returned.
     */
    hints.ai_flags = AI_PASSIVE;

    /* Add all the requested addresses. */
    for (i = 0; i < bind_addresses.n; i++) {
        val = bind_addresses.data[i];
        hints.ai_socktype = BIND_FAMILIES[val.type];

        /* Call getaddrinfo passing the port "0" to support cases when the
         * address is NULL. */
        err = getaddrinfo(val.address, "0", &hints, &result);
        if (err) {
            krb5_klog_syslog(LOG_ERR,
                             _("Failed getting address info (for %s): %s"),
                             val.address == NULL ? "<wildcard>" : val.address,
                             gai_strerror(err));
            ret = EIO;
            goto cleanup;
        }

        /*
         * Loop through all the sockets that getaddrinfo could find to match
         * the requested address. In case of the default wildcard, this should
         * usually have two results, one for each of ipv4 and ipv6, or one or
         * the other, depending on the system.
         *
         * NOTE: This could be put in its own function to break this one up
         * if it gets too big - @sarahday
         */
        for (r_next = result; r_next != NULL; r_next = r_next->ai_next) {
            /* Make sure getaddrinfo returned a socket with the same type that
             * was requested. */
            assert(hints.ai_socktype == r_next->ai_socktype);
            /* Set the port number for the socket. */
            sa_setport(r_next->ai_addr, val.port);

            /* Setup the socket creation flags. */
            flags = 0;
            flags |= val.type == udp || val.type == tcp ? NBIO : 0;
            flags |= val.type == tcp ? LISTEN : 0;
            flags |= val.type == tcp ? NOLINGER : 0;

            /* When the family is udp and the wildcard address is requested we
             * want to use ip PktInfo if it's available. */
            flags |= val.type == udp && val.address == NULL &&
                /* Check for general PktInfo support */
                CHECK_PKTINFO_SUPPORT &&
                /* Check for IPv4 PktInfo support. */
                (CHECK_IP_PKTINFO || r_next->ai_family != AF_INET) &&
                /* Check for IPv6 PktInfo support. */
                (CHECK_IPV6_PKTINFO || r_next->ai_family != AF_INET6)
                ? PKTINFO : 0;

#ifndef HAVE_FULL_PKTINFO_SUPPORT /* Only include workaround when needed */
            /*
             * Check if the address is wildcard, UDP, and PKTINFO was not set.
             * In this case some special hackery needs to be done. :-/
             */
            if (val.type == udp && val.address == NULL && !(flags & PKTINFO)) {
                krb5_klog_syslog(LOG_DEBUG,
                                 _("System missing pktinfo support. "
                                   "Trying to use local addresses."));
                err =
                    WORKAROUND_setup_local_addresses(data, &val,
                                                     r_next->ai_family,
                                                     flags,
                                                     VERTO_CALLBACK[val.type],
                                                     CONN_UDP,
                                                     FD_ADDED_CALLBACK
                                                     [val.type]);
                if (err != 0) {
                    ret = err;
                    goto cleanup;
                }

                krb5_klog_syslog(LOG_DEBUG,
                                 _("Successfully bound to local addresses"));
                /* We're done here, so continue to the next result. */
                continue;
            }
#endif /* End of workaround for when pktinfo isn't available. */

            /* Figure out the conn_type for the socket. */

            /*
             * TODO @sarahday Figure out a better way to do this. The two
             * different udp connection types are adding this ugly code.
             */
            switch (val.type) {
            case udp:
                if (flags & PKTINFO)
                    ctype = CONN_UDP_PKTINFO;
                else
                    ctype = CONN_UDP;
                break;
            case tcp:
                ctype = CONN_TCP_LISTENER;
                break;
            case rpc:
                ctype = CONN_RPC_LISTENER;
                break;
            default:
                ret = EINVAL;
                goto cleanup;
            }

            /* Cross your fingers, it's time to setup the socket! */
            err = setup_socket(data, &val, r_next->ai_addr, flags,
                               VERTO_CALLBACK[val.type], ctype,
                               FD_ADDED_CALLBACK[val.type]);
            if (err != 0) {
                /* Well, that didn't go very well... */
                krb5_klog_syslog(LOG_ERR,
                                 _("Failed setting up a %s socket (for %s)"),
                                 BIND_TYPE_NAMES[val.type],
                                 paddr(r_next->ai_addr));
                ret = err;
                goto cleanup;
            }
        }

        freeaddrinfo(result);
        result = NULL;
        ret = 0;
    }

  cleanup:
    freeaddrinfo(result);
    return ret;
}

krb5_error_code
loop_setup_network(verto_ctx *ctx, void *handle, const char *prog)
{
    struct socksetup setup_data;
    verto_ev *ev;
    int i, ret;

    /* Check to make sure that at least one address was added to the loop. */
    if (bind_addresses.n == 0)
        return EINVAL;

    /* Close any open connections. */
    FOREACH_ELT(events, i, ev)
        verto_del(ev);
    events.n = 0;

    setup_data.ctx = ctx;
    setup_data.handle = handle;
    setup_data.prog = prog;
    setup_data.retval = 0;
    krb5_klog_syslog(LOG_INFO, _("setting up network..."));
    ret = setup_addresses(&setup_data);
    if (ret != 0) {
        com_err(prog, ret, _("Error setting up network"));
        exit(1);
    }
    krb5_klog_syslog (LOG_INFO, _("set up %d sockets"), (int) events.n);
    if (events.n == 0) {
        /*
         * If no sockets were setup then something bad happened. A net server
         * without a socket isn't much of a net server.
         */
        com_err(prog, 0, _("no sockets set up?"));
        exit (1);
    }

    return 0;
}

void
init_addr(krb5_fulladdr *faddr, struct sockaddr *sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        faddr->address->addrtype = ADDRTYPE_INET;
        faddr->address->length = 4;
        faddr->address->contents = (krb5_octet *) &sa2sin(sa)->sin_addr;
        faddr->port = ntohs(sa2sin(sa)->sin_port);
        break;
    case AF_INET6:
        if (IN6_IS_ADDR_V4MAPPED(&sa2sin6(sa)->sin6_addr)) {
            faddr->address->addrtype = ADDRTYPE_INET;
            faddr->address->length = 4;
            faddr->address->contents = 12 + (krb5_octet *) &sa2sin6(sa)->sin6_addr;
        } else {
            faddr->address->addrtype = ADDRTYPE_INET6;
            faddr->address->length = 16;
            faddr->address->contents = (krb5_octet *) &sa2sin6(sa)->sin6_addr;
        }
        faddr->port = ntohs(sa2sin6(sa)->sin6_port);
        break;
    default:
        faddr->address->addrtype = -1;
        faddr->address->length = 0;
        faddr->address->contents = 0;
        faddr->port = 0;
        break;
    }
}

/*
 * This holds whatever additional information might be needed to
 * properly send back to the client from the correct local address.
 *
 * In this case, we only need one datum so far: On Mac OS X, the
 * kernel doesn't seem to like sending from link-local addresses
 * unless we specify the correct interface.
 */

union aux_addressing_info {
    int ipv6_ifindex;
};

static int
recv_from_to(int s, void *buf, size_t len, int flags,
             struct sockaddr *from, socklen_t *fromlen,
             struct sockaddr *to, socklen_t *tolen,
             union aux_addressing_info *auxaddr)
{
#if (!defined(IP_PKTINFO) && !defined(IPV6_PKTINFO)) || !defined(CMSG_SPACE)
    if (to && tolen) {
        /* Clobber with something recognizeable in case we try to use
           the address.  */
        memset(to, 0x40, *tolen);
        *tolen = 0;
    }

    return recvfrom(s, buf, len, flags, from, fromlen);
#else
    int r;
    struct iovec iov;
    char cmsg[CMSG_SPACE(sizeof(union pktinfo))];
    struct cmsghdr *cmsgptr;
    struct msghdr msg;

    if (!to || !tolen)
        return recvfrom(s, buf, len, flags, from, fromlen);

    /* Clobber with something recognizeable in case we can't extract
       the address but try to use it anyways.  */
    memset(to, 0x40, *tolen);

    iov.iov_base = buf;
    iov.iov_len = len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = from;
    msg.msg_namelen = *fromlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
    msg.msg_controllen = sizeof(cmsg);

    r = recvmsg(s, &msg, flags);
    if (r < 0)
        return r;
    *fromlen = msg.msg_namelen;

    /* On Darwin (and presumably all *BSD with KAME stacks),
       CMSG_FIRSTHDR doesn't check for a non-zero controllen.  RFC
       3542 recommends making this check, even though the (new) spec
       for CMSG_FIRSTHDR says it's supposed to do the check.  */
    if (msg.msg_controllen) {
        cmsgptr = CMSG_FIRSTHDR(&msg);
        while (cmsgptr) {
#ifdef IP_PKTINFO
            if (cmsgptr->cmsg_level == IPPROTO_IP
                && cmsgptr->cmsg_type == IP_PKTINFO
                && *tolen >= sizeof(struct sockaddr_in)) {
                struct in_pktinfo *pktinfo;
                memset(to, 0, sizeof(struct sockaddr_in));
                pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsgptr);
                ((struct sockaddr_in *)to)->sin_addr = pktinfo->ipi_addr;
                ((struct sockaddr_in *)to)->sin_family = AF_INET;
                *tolen = sizeof(struct sockaddr_in);
                return r;
            }
#endif
#if defined(IPV6_PKTINFO) && defined(HAVE_STRUCT_IN6_PKTINFO)
            if (cmsgptr->cmsg_level == IPPROTO_IPV6
                && cmsgptr->cmsg_type == IPV6_PKTINFO
                && *tolen >= sizeof(struct sockaddr_in6)) {
                struct in6_pktinfo *pktinfo;
                memset(to, 0, sizeof(struct sockaddr_in6));
                pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsgptr);
                ((struct sockaddr_in6 *)to)->sin6_addr = pktinfo->ipi6_addr;
                ((struct sockaddr_in6 *)to)->sin6_family = AF_INET6;
                *tolen = sizeof(struct sockaddr_in6);
                auxaddr->ipv6_ifindex = pktinfo->ipi6_ifindex;
                return r;
            }
#endif
            cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
        }
    }
    /* No info about destination addr was available.  */
    *tolen = 0;
    return r;
#endif
}

static int
send_to_from(int s, void *buf, size_t len, int flags,
             const struct sockaddr *to, socklen_t tolen,
             const struct sockaddr *from, socklen_t fromlen,
             union aux_addressing_info *auxaddr)
{
#if (!defined(IP_PKTINFO) && !defined(IPV6_PKTINFO)) || !defined(CMSG_SPACE)
    return sendto(s, buf, len, flags, to, tolen);
#else
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsgptr;
    char cbuf[CMSG_SPACE(sizeof(union pktinfo))];

    if (from == 0 || fromlen == 0 || from->sa_family != to->sa_family) {
    use_sendto:
        return sendto(s, buf, len, flags, to, tolen);
    }

    iov.iov_base = buf;
    iov.iov_len = len;
    /* Truncation?  */
    if (iov.iov_len != len)
        return EINVAL;
    memset(cbuf, 0, sizeof(cbuf));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *) to;
    msg.msg_namelen = tolen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    /* CMSG_FIRSTHDR needs a non-zero controllen, or it'll return NULL
       on Linux.  */
    msg.msg_controllen = sizeof(cbuf);
    cmsgptr = CMSG_FIRSTHDR(&msg);
    msg.msg_controllen = 0;

    switch (from->sa_family) {
#if defined(IP_PKTINFO)
    case AF_INET:
        if (fromlen != sizeof(struct sockaddr_in))
            goto use_sendto;
        cmsgptr->cmsg_level = IPPROTO_IP;
        cmsgptr->cmsg_type = IP_PKTINFO;
        cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        {
            struct in_pktinfo *p = (struct in_pktinfo *)CMSG_DATA(cmsgptr);
            const struct sockaddr_in *from4 = (const struct sockaddr_in *)from;
            p->ipi_spec_dst = from4->sin_addr;
        }
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
        break;
#endif
#if defined(IPV6_PKTINFO) && defined(HAVE_STRUCT_IN6_PKTINFO)
    case AF_INET6:
        if (fromlen != sizeof(struct sockaddr_in6))
            goto use_sendto;
        cmsgptr->cmsg_level = IPPROTO_IPV6;
        cmsgptr->cmsg_type = IPV6_PKTINFO;
        cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        {
            struct in6_pktinfo *p = (struct in6_pktinfo *)CMSG_DATA(cmsgptr);
            const struct sockaddr_in6 *from6 =
                (const struct sockaddr_in6 *)from;
            p->ipi6_addr = from6->sin6_addr;
            /*
             * Because of the possibility of asymmetric routing, we
             * normally don't want to specify an interface.  However,
             * Mac OS X doesn't like sending from a link-local address
             * (which can come up in testing at least, if you wind up
             * with a "foo.local" name) unless we do specify the
             * interface.
             */
            if (IN6_IS_ADDR_LINKLOCAL(&from6->sin6_addr))
                p->ipi6_ifindex = auxaddr->ipv6_ifindex;
            /* otherwise, already zero */
        }
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
        break;
#endif
    default:
        goto use_sendto;
    }
    return sendmsg(s, &msg, flags);
#endif
}

struct udp_dispatch_state {
    void *handle;
    const char *prog;
    int port_fd;
    krb5_address addr;
    krb5_fulladdr faddr;
    socklen_t saddr_len;
    socklen_t daddr_len;
    struct sockaddr_storage saddr;
    struct sockaddr_storage daddr;
    union aux_addressing_info auxaddr;
    krb5_data request;
    char pktbuf[MAX_DGRAM_SIZE];
};

static void
process_packet_response(void *arg, krb5_error_code code, krb5_data *response)
{
    struct udp_dispatch_state *state = arg;
    int cc;

    if (code)
        com_err(state->prog ? state->prog : NULL, code,
                _("while dispatching (udp)"));
    if (code || response == NULL)
        goto out;

    cc = send_to_from(state->port_fd, response->data,
                      (socklen_t) response->length, 0,
                      (struct sockaddr *)&state->saddr, state->saddr_len,
                      (struct sockaddr *)&state->daddr, state->daddr_len,
                      &state->auxaddr);
    if (cc == -1) {
        /* Note that the local address (daddr*) has no port number
         * info associated with it. */
        char saddrbuf[NI_MAXHOST], sportbuf[NI_MAXSERV];
        char daddrbuf[NI_MAXHOST];
        int e = errno;

        if (getnameinfo((struct sockaddr *)&state->daddr, state->daddr_len,
                        daddrbuf, sizeof(daddrbuf), 0, 0,
                        NI_NUMERICHOST) != 0) {
            strlcpy(daddrbuf, "?", sizeof(daddrbuf));
        }

        if (getnameinfo((struct sockaddr *)&state->saddr, state->saddr_len,
                        saddrbuf, sizeof(saddrbuf), sportbuf, sizeof(sportbuf),
                        NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
            strlcpy(saddrbuf, "?", sizeof(saddrbuf));
            strlcpy(sportbuf, "?", sizeof(sportbuf));
        }

        com_err(state->prog, e, _("while sending reply to %s/%s from %s"),
                saddrbuf, sportbuf, daddrbuf);
        goto out;
    }
    if ((size_t)cc != response->length) {
        com_err(state->prog, 0, _("short reply write %d vs %d\n"),
                response->length, cc);
    }

out:
    krb5_free_data(get_context(state->handle), response);
    free(state);
}

static void
process_packet(verto_ctx *ctx, verto_ev *ev)
{
    int cc;
    struct connection *conn;
    struct udp_dispatch_state *state;

    conn = verto_get_private(ev);

    state = malloc(sizeof(*state));
    if (!state) {
        com_err(conn->prog, ENOMEM, _("while dispatching (udp)"));
        return;
    }

    state->handle = conn->handle;
    state->prog = conn->prog;
    state->port_fd = verto_get_fd(ev);
    assert(state->port_fd >= 0);

    state->saddr_len = sizeof(state->saddr);
    state->daddr_len = sizeof(state->daddr);
    memset(&state->auxaddr, 0, sizeof(state->auxaddr));
    cc = recv_from_to(state->port_fd, state->pktbuf, sizeof(state->pktbuf), 0,
                      (struct sockaddr *)&state->saddr, &state->saddr_len,
                      (struct sockaddr *)&state->daddr, &state->daddr_len,
                      &state->auxaddr);
    if (cc == -1) {
        if (errno != EINTR && errno != EAGAIN
            /*
             * This is how Linux indicates that a previous transmission was
             * refused, e.g., if the client timed out before getting the
             * response packet.
             */
            && errno != ECONNREFUSED
        )
            com_err(conn->prog, errno, _("while receiving from network"));
        free(state);
        return;
    }
    if (!cc) { /* zero-length packet? */
        free(state);
        return;
    }

#if 0
    if (state->daddr_len > 0) {
        char addrbuf[100];
        if (getnameinfo(ss2sa(&state->daddr), state->daddr_len,
                        addrbuf, sizeof(addrbuf),
                        0, 0, NI_NUMERICHOST))
            strlcpy(addrbuf, "?", sizeof(addrbuf));
        com_err(conn->prog, 0, _("pktinfo says local addr is %s"), addrbuf);
    }
#endif

    if (state->daddr_len == 0 && conn->type == CONN_UDP) {
        /*
         * If the PKTINFO option isn't set, this socket should be bound to a
         * specific local address.  This info probably should've been saved in
         * our socket data structure at setup time.
         */
        state->daddr_len = sizeof(state->daddr);
        if (getsockname(state->port_fd, (struct sockaddr *)&state->daddr,
                        &state->daddr_len) != 0)
            state->daddr_len = 0;
        /* On failure, keep going anyways. */
    }

    state->request.length = cc;
    state->request.data = state->pktbuf;
    state->faddr.address = &state->addr;
    init_addr(&state->faddr, ss2sa(&state->saddr));
    /* This address is in net order. */
    dispatch(state->handle, ss2sa(&state->daddr), &state->faddr,
             &state->request, 0, ctx, process_packet_response, state);
}

static int
kill_lru_tcp_or_rpc_connection(void *handle, verto_ev *newev)
{
    struct connection *c = NULL, *oldest_c = NULL;
    verto_ev *ev, *oldest_ev = NULL;
    int i, fd = -1;

    krb5_klog_syslog(LOG_INFO, _("too many connections"));

    FOREACH_ELT (events, i, ev) {
        if (ev == newev)
            continue;

        c = verto_get_private(ev);
        if (!c)
            continue;
        if (c->type != CONN_TCP && c->type != CONN_RPC)
            continue;
#if 0
        krb5_klog_syslog(LOG_INFO, "fd %d started at %ld",
                         verto_get_fd(oldest_ev),
                         c->start_time);
#endif
        if (oldest_c == NULL
            || oldest_c->start_time > c->start_time) {
            oldest_ev = ev;
            oldest_c = c;
        }
    }
    if (oldest_c != NULL) {
        krb5_klog_syslog(LOG_INFO, _("dropping %s fd %d from %s"),
                         c->type == CONN_RPC ? "rpc" : "tcp",
                         verto_get_fd(oldest_ev), oldest_c->addrbuf);
        if (oldest_c->type == CONN_RPC)
            oldest_c->rpc_force_close = 1;
        verto_del(oldest_ev);
    }
    return fd;
}

static void
accept_tcp_connection(verto_ctx *ctx, verto_ev *ev)
{
    int s;
    struct sockaddr_storage addr_s;
    struct sockaddr *addr = (struct sockaddr *)&addr_s;
    socklen_t addrlen = sizeof(addr_s);
    struct socksetup sockdata;
    struct connection *newconn, *conn;
    char tmpbuf[10];
    verto_ev *newev;

    conn = verto_get_private(ev);
    s = accept(verto_get_fd(ev), addr, &addrlen);
    if (s < 0)
        return;
    set_cloexec_fd(s);
#ifndef _WIN32
    if (s >= FD_SETSIZE) {
        close(s);
        return;
    }
#endif
    setnbio(s), setnolinger(s), setkeepalive(s);

    sockdata.ctx = ctx;
    sockdata.handle = conn->handle;
    sockdata.prog = conn->prog;
    sockdata.retval = 0;

    newev = add_tcp_read_fd(&sockdata, s);
    if (newev == NULL) {
        close(s);
        return;
    }
    newconn = verto_get_private(newev);

    if (getnameinfo((struct sockaddr *)&addr_s, addrlen,
                    newconn->addrbuf, sizeof(newconn->addrbuf),
                    tmpbuf, sizeof(tmpbuf),
                    NI_NUMERICHOST | NI_NUMERICSERV))
        strlcpy(newconn->addrbuf, "???", sizeof(newconn->addrbuf));
    else {
        char *p, *end;
        p = newconn->addrbuf;
        end = p + sizeof(newconn->addrbuf);
        p += strlen(p);
        if ((size_t)(end - p) > 2 + strlen(tmpbuf)) {
            *p++ = '.';
            strlcpy(p, tmpbuf, end - p);
        }
    }
#if 0
    krb5_klog_syslog(LOG_INFO, "accepted TCP connection on socket %d from %s",
                     s, newconn->addrbuf);
#endif

    newconn->addr_s = addr_s;
    newconn->addrlen = addrlen;
    newconn->bufsiz = 1024 * 1024;
    newconn->buffer = malloc(newconn->bufsiz);
    newconn->start_time = time(0);

    if (++tcp_or_rpc_data_counter > max_tcp_or_rpc_data_connections)
        kill_lru_tcp_or_rpc_connection(conn->handle, newev);

    if (newconn->buffer == 0) {
        com_err(conn->prog, errno,
                _("allocating buffer for new TCP session from %s"),
                newconn->addrbuf);
        verto_del(newev);
        return;
    }
    newconn->offset = 0;
    newconn->faddr.address = &newconn->kaddr;
    init_addr(&newconn->faddr, ss2sa(&newconn->addr_s));
    SG_SET(&newconn->sgbuf[0], newconn->lenbuf, 4);
    SG_SET(&newconn->sgbuf[1], 0, 0);
}

struct tcp_dispatch_state {
    struct sockaddr_storage local_saddr;
    struct connection *conn;
    krb5_data request;
    verto_ctx *ctx;
    int sock;
};

static void
process_tcp_response(void *arg, krb5_error_code code, krb5_data *response)
{
    struct tcp_dispatch_state *state = arg;
    verto_ev *ev;

    assert(state);
    state->conn->response = response;

    if (code)
        com_err(state->conn->prog, code, _("while dispatching (tcp)"));
    if (code || !response)
        goto kill_tcp_connection;

    /* Queue outgoing response. */
    store_32_be(response->length, state->conn->lenbuf);
    SG_SET(&state->conn->sgbuf[1], response->data, response->length);
    state->conn->sgp = state->conn->sgbuf;
    state->conn->sgnum = 2;

    ev = make_event(state->ctx, VERTO_EV_FLAG_IO_WRITE | VERTO_EV_FLAG_PERSIST,
                    process_tcp_connection_write, state->sock, state->conn, 1);
    if (ev) {
        free(state);
        return;
    }

kill_tcp_connection:
    tcp_or_rpc_data_counter--;
    free_connection(state->conn);
    close(state->sock);
    free(state);
}

/* Creates the tcp_dispatch_state and deletes the verto event. */
static struct tcp_dispatch_state *
prepare_for_dispatch(verto_ctx *ctx, verto_ev *ev)
{
    struct tcp_dispatch_state *state;

    state = malloc(sizeof(*state));
    if (!state) {
        krb5_klog_syslog(LOG_ERR, _("error allocating tcp dispatch private!"));
        return NULL;
    }
    state->conn = verto_get_private(ev);
    state->sock = verto_get_fd(ev);
    state->ctx = ctx;
    verto_set_private(ev, NULL, NULL); /* Don't close the fd or free conn! */
    remove_event_from_set(ev); /* Remove it from the set. */
    verto_del(ev);
    return state;
}

static void
process_tcp_connection_read(verto_ctx *ctx, verto_ev *ev)
{
    struct tcp_dispatch_state *state = NULL;
    struct connection *conn = NULL;
    ssize_t nread;
    size_t len;

    conn = verto_get_private(ev);

    /*
     * Read message length and data into one big buffer, already allocated
     * at connect time.  If we have a complete message, we stop reading, so
     * we should only be here if there is no data in the buffer, or only an
     * incomplete message.
     */
    if (conn->offset < 4) {
        krb5_data *response = NULL;

        /* msglen has not been computed.  XXX Doing at least two reads
         * here, letting the kernel worry about buffering. */
        len = 4 - conn->offset;
        nread = SOCKET_READ(verto_get_fd(ev),
                            conn->buffer + conn->offset, len);
        if (nread < 0) /* error */
            goto kill_tcp_connection;
        if (nread == 0) /* eof */
            goto kill_tcp_connection;
        conn->offset += nread;
        if (conn->offset == 4) {
            unsigned char *p = (unsigned char *)conn->buffer;
            conn->msglen = load_32_be(p);
            if (conn->msglen > conn->bufsiz - 4) {
                krb5_error_code err;
                /* Message too big. */
                krb5_klog_syslog(LOG_ERR, _("TCP client %s wants %lu bytes, "
                                            "cap is %lu"), conn->addrbuf,
                                 (unsigned long) conn->msglen,
                                 (unsigned long) conn->bufsiz - 4);
                /* XXX Should return an error.  */
                err = make_toolong_error (conn->handle,
                                          &response);
                if (err) {
                    krb5_klog_syslog(LOG_ERR, _("error constructing "
                                                "KRB_ERR_FIELD_TOOLONG error! %s"),
                                     error_message(err));
                    goto kill_tcp_connection;
                }

                state = prepare_for_dispatch(ctx, ev);
                if (!state) {
                    krb5_free_data(get_context(conn->handle), response);
                    goto kill_tcp_connection;
                }
                process_tcp_response(state, 0, response);
            }
        }
    } else {
        /* msglen known. */
        socklen_t local_saddrlen = sizeof(struct sockaddr_storage);
        struct sockaddr *local_saddrp = NULL;

        len = conn->msglen - (conn->offset - 4);
        nread = SOCKET_READ(verto_get_fd(ev),
                            conn->buffer + conn->offset, len);
        if (nread < 0) /* error */
            goto kill_tcp_connection;
        if (nread == 0) /* eof */
            goto kill_tcp_connection;
        conn->offset += nread;
        if (conn->offset < conn->msglen + 4)
            return;

        /* Have a complete message, and exactly one message. */
        state = prepare_for_dispatch(ctx, ev);
        if (!state)
            goto kill_tcp_connection;

        state->request.length = conn->msglen;
        state->request.data = conn->buffer + 4;

        if (getsockname(verto_get_fd(ev), ss2sa(&state->local_saddr),
                        &local_saddrlen) == 0)
            local_saddrp = ss2sa(&state->local_saddr);

        dispatch(state->conn->handle, local_saddrp, &conn->faddr,
                 &state->request, 1, ctx, process_tcp_response, state);
    }

    return;

kill_tcp_connection:
    verto_del(ev);
}

static void
process_tcp_connection_write(verto_ctx *ctx, verto_ev *ev)
{
    struct connection *conn;
    SOCKET_WRITEV_TEMP tmp;
    ssize_t nwrote;
    int sock;

    conn = verto_get_private(ev);
    sock = verto_get_fd(ev);

    nwrote = SOCKET_WRITEV(sock, conn->sgp,
                           conn->sgnum, tmp);
    if (nwrote > 0) { /* non-error and non-eof */
        while (nwrote) {
            sg_buf *sgp = conn->sgp;
            if ((size_t)nwrote < SG_LEN(sgp)) {
                SG_ADVANCE(sgp, (size_t)nwrote);
                nwrote = 0;
            } else {
                nwrote -= SG_LEN(sgp);
                conn->sgp++;
                conn->sgnum--;
                if (conn->sgnum == 0 && nwrote != 0)
                    abort();
            }
        }

        /* If we still have more data to send, just return so that
         * the main loop can call this function again when the socket
         * is ready for more writing. */
        if (conn->sgnum > 0)
            return;
    }

    /* Finished sending.  We should go back to reading, though if we
     * sent a FIELD_TOOLONG error in reply to a length with the high
     * bit set, RFC 4120 says we have to close the TCP stream. */
    verto_del(ev);
}

void
loop_free(verto_ctx *ctx)
{
    int i;
    struct bind_address val;

    verto_free(ctx);

    /* Free all the addresses added to net-server */
    FOREACH_ELT(bind_addresses, i, val)
        free(val.address);

    FREE_SET_DATA(bind_addresses);
    FREE_SET_DATA(events);
}

static int
have_event_for_fd(int fd)
{
    verto_ev *ev;
    int i;

    FOREACH_ELT(events, i, ev) {
        if (verto_get_fd(ev) == fd)
            return 1;
    }

    return 0;
}

static void
accept_rpc_connection(verto_ctx *ctx, verto_ev *ev)
{
    struct socksetup sockdata;
    struct connection *conn;
    fd_set fds;
    register int s;

    conn = verto_get_private(ev);

    sockdata.ctx = ctx;
    sockdata.handle = conn->handle;
    sockdata.prog = conn->prog;
    sockdata.retval = 0;

    /* Service the woken RPC listener descriptor. */
    FD_ZERO(&fds);
    FD_SET(verto_get_fd(ev), &fds);
    svc_getreqset(&fds);

    /* Scan svc_fdset for any new connections. */
    for (s = 0; s < FD_SETSIZE; s++) {
        struct sockaddr_storage addr_s;
        struct sockaddr *addr = (struct sockaddr *) &addr_s;
        socklen_t addrlen = sizeof(addr_s);
        struct connection *newconn;
        char tmpbuf[10];
        verto_ev *newev;

        /* If we already have this fd, continue. */
        if (!FD_ISSET(s, &svc_fdset) || have_event_for_fd(s))
            continue;

        newev = add_rpc_data_fd(&sockdata, s);
        if (newev == NULL)
            continue;
        newconn = verto_get_private(newev);

        set_cloexec_fd(s);
#if 0
        setnbio(s), setnolinger(s), setkeepalive(s);
#endif

        if (getpeername(s, addr, &addrlen) ||
            getnameinfo(addr, addrlen,
                        newconn->addrbuf,
                        sizeof(newconn->addrbuf),
                        tmpbuf, sizeof(tmpbuf),
                        NI_NUMERICHOST | NI_NUMERICSERV)) {
            strlcpy(newconn->addrbuf, "???",
                    sizeof(newconn->addrbuf));
        } else {
            char *p, *end;
            p = newconn->addrbuf;
            end = p + sizeof(newconn->addrbuf);
            p += strlen(p);
            if ((size_t)(end - p) > 2 + strlen(tmpbuf)) {
                *p++ = '.';
                strlcpy(p, tmpbuf, end - p);
            }
        }
#if 0
        krb5_klog_syslog(LOG_INFO, _("accepted RPC connection on socket %d "
                                     "from %s"), s, newconn->addrbuf);
#endif

        newconn->addr_s = addr_s;
        newconn->addrlen = addrlen;
        newconn->start_time = time(0);

        if (++tcp_or_rpc_data_counter > max_tcp_or_rpc_data_connections)
            kill_lru_tcp_or_rpc_connection(newconn->handle, newev);

        newconn->faddr.address = &newconn->kaddr;
        init_addr(&newconn->faddr, ss2sa(&newconn->addr_s));
    }
}

static void
process_rpc_connection(verto_ctx *ctx, verto_ev *ev)
{
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(verto_get_fd(ev), &fds);
    svc_getreqset(&fds);

    if (!FD_ISSET(verto_get_fd(ev), &svc_fdset))
        verto_del(ev);
}

#endif /* INET */



