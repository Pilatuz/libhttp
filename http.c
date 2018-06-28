/**
 * @file
 * @brief HTTP client/server implementation.
 * @author Sergey Polichnoy <pilatuz@gmail.com>
 */
#include "http.h"

// logging tweaks
#undef  LOG_MODULE
#define LOG_MODULE "http"
#undef  LOG_LEVEL
#if defined(HTTP_LOG_LEVEL)
# define LOG_LEVEL HTTP_LOG_LEVEL
#else
# define LOG_LEVEL 9
#endif // HTTP_LOG_LEVEL
#include "misc.h"

#include <wolfssl/wolfcrypt/hash.h> // for SHA-1

#ifndef __linux__ // TODO: MQX platform detection macro???
#include <mqx.h>
#include <rtcs.h>
#define hostent hostent_struct
#define socklen_t uint16_t
#define port_n2h(x) (x)
#define port_h2n(x) (x)

#elif defined(__linux__) // Linux
#include <netdb.h>
#include <strings.h>

#define port_n2h(x) ntohs(x)
#define port_h2n(x) htons(x)
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

/**
 * @brief Extract just IPv4 components.
 *
 * Should be used with "%d.%d.%d.%d" printf format.
 */
#define PRINT_IPV4_ADDR(addr)           \
    (addr.sin_addr.s_addr >> 0)&0x0ff,  \
    (addr.sin_addr.s_addr >> 8)&0x0ff,  \
    (addr.sin_addr.s_addr >> 16)&0x0ff, \
    (addr.sin_addr.s_addr >> 24)&0x0ff
// TODO: use IPBYTES from MQX


/**
 * @brief Extract IPv4 components and port number.
 *
 * Should be used with "%d.%d.%d.%d:%d" printf format.
 */
#define PRINT_IPV4_ADDR_AND_PORT(addr)  \
    PRINT_IPV4_ADDR(addr),              \
    port_n2h(addr.sin_port)


/*
 * ssl_proto_string() implementation.
 */
const char* ssl_proto_string(enum SSL_Proto proto)
{
    switch (proto)
    {
    case SSL_PROTO_SSLv3:               return "SSLv3";
    case SSL_PROTO_TLSv1_0:             return "TLSv1.0";
    case SSL_PROTO_TLSv1_1:             return "TLSv1.1";
    case SSL_PROTO_TLSv1_2:             return "TLSv1.2";
    case SSL_PROTO_TLSv1_3:             return "TLSv1.3";
    case SSL_PROTO_TLSv1_2_TO_SSLv3:    return "SSLv3-TLSv1.2";
    }

    return "UNKNOWN";
}


/*
 * http_method_string() implementation.
 */
const char* http_method_string(enum HTTP_Method method)
{
    switch (method)
    {
    case HTTP_GET :     return "GET";
    case HTTP_PUT:      return "PUT";
    case HTTP_POST:     return "POST";
    case HTTP_HEAD:     return "HEAD";
    case HTTP_DELETE:   return "DELETE";
    case HTTP_CONNECT:  return "CONNECT";
    case HTTP_OPTIONS:  return "OPTIONS";

    case HTTP_UNKNOWN_METHOD: break;
    }

    return "UNKNOWN";
}


/*
 * http_proto_string() implementation.
 */
const char* http_proto_string(enum HTTP_Proto proto)
{
    switch (proto)
    {
    case HTTP_PROTO_1_0:    return "HTTP/1.0";
    case HTTP_PROTO_1_1:    return "HTTP/1.1";

    case HTTP_UNKNOWN_PROTO: break;
    }

    return "UNKNOWN";
}


/*
 * http_status_reason() implementation.
 */
const char* http_status_reason(int status)
{
    switch (status)
    {
    case HTTP_STATUS_CONTINUE:                  return "Continue";
    //case 101:                                 return "Switching Protocols";
    case HTTP_STATUS_OK:                        return "OK";
    case HTTP_STATUS_CREATED:                   return "Created";
    case HTTP_STATUS_ACCEPTED:                  return "Accepted";
    //case 203:                                 return "Non-Authoritative Information";
    case HTTP_STATUS_NO_CONTENT:                return "No Content";
    case HTTP_STATUS_RESET_CONTENT:             return "Reset Content";
    case HTTP_STATUS_PARTIAL_CONTENT:           return "Partial Content";
    //case 300:                                 return "Multiple Choices";
    case HTTP_STATUS_MOVED_PERMANENTLY:         return "Moved Permanently";
    case HTTP_STATUS_FOUND:                     return "Found";
    //case 303:                                 return "See Other";
    case HTTP_STATUS_NOT_MODIFIED:              return "Not Modified";
    //case 305:                                 return "Use Proxy";
    //case 307:                                 return "Temporary Redirect";
    case HTTP_STATUS_BAD_REQUEST:               return "Bad Request";
    case HTTP_STATUS_UNAUTHORIZED:              return "Unauthorized";
    //case 402:                                 return "Payment Required";
    case HTTP_STATUS_FORBIDDEN:                 return "Forbidden";
    case HTTP_STATUS_NOT_FOUND:                 return "Not Found";
    case HTTP_STATUS_METHOD_NOT_ALLOWED:        return "Method Not Allowed";
    case HTTP_STATUS_NOT_ACCEPTABLE:            return "Not Acceptable";
    //case 407:                                 return "Proxy Authentication Required";
    case HTTP_STATUS_REQUEST_TIMEOUT:           return "Request Time-out";
    //case 409:                                 return "Conflict";
    //case 410:                                 return "Gone";
    //case 411:                                 return "Length Required";
    //case 412:                                 return "Precondition Failed";
    //case 413:                                 return "Request Entity Too Large";
    //case 414:                                 return "Request-URI Too Large";
    //case 415:                                 return "Unsupported Media Type";
    //case 416:                                 return "Requested range not satisfiable";
    //case 417:                                 return "Expectation Failed";
    case HTTP_STATUS_INTERNAL_SERVER_ERROR:     return "Internal Server Error";
    case HTTP_STATUS_NOT_IMPLEMENTED:           return "Not Implemented";
    //case 502:                                 return "Bad Gateway";
    case HTTP_STATUS_SERVICE_UNAVAILABLE:       return "Service Unavailable";
    //case 504:                                 return "Gateway Time-out";
    //case 505:                                 return "HTTP Version not supported";
    }

    return 0; // unknown status
}


/*
 * http_connection_header_parse() implementation.
 */
enum HTTP_HeaderConnection http_header_connection_parse(const char *value)
{
    if (0 == strcasecmp(value, "close"))
        return HTTP_CONNECTION_CLOSE;
    else if (0 == strcasecmp(value, "keep-alive"))
        return HTTP_CONNECTION_KEEP_ALIVE;

    return HTTP_CONNECTION_UNKNOWN;
}


/*
 * http_connection_header_string() implementation.
 */
const char* http_header_connection_string(enum HTTP_HeaderConnection connection)
{
    switch (connection)
    {
    case HTTP_CONNECTION_CLOSE:         return "close";
    case HTTP_CONNECTION_KEEP_ALIVE:    return "keep-alive";

    // all others...
    case HTTP_CONNECTION_MISSING: break;
    case HTTP_CONNECTION_UNKNOWN: break;
    }

    return "unknown";
}

// HTTP connection
#if defined(HTTP_CLIENT) || defined(HTTP_SERVER)

/**
 * @brief Connection internal flags.
 */
enum HTTP_ConnInternalFlags
{
    // client side
    CONN_FLAG_REQUEST_LINE_SENT         = 0x00010000, /**< @brief Request line sent. Continue with sending request headers. */
    CONN_FLAG_REQUEST_HEADERS_SENT      = 0x00020000, /**< @brief All request headers sent. Continue with request body. */
    CONN_FLAG_REQUEST_BODY_SENT         = 0x00040000, /**< @brief Request body sent. Coninue with response receiving. */
    CONN_FLAG_REQUEST_HOST_HEADER_SENT  = 0x00080000, /**< @brief "Host" request header sent. */
    CONN_FLAG_RESPONSE_STATUS_RECEIVED  = 0x00100000, /**< @brief Response status line received. Continue with response headers. */
    CONN_FLAG_RESPONSE_HEADERS_RECEIVED = 0x00200000, /**< @brief All response headers received. Continue with response body. */

    // server side
    CONN_FLAG_REQUEST_LINE_RECEIVED     = 0x01000000, /**< @brief Request line received. Continue receiving request headers. */
    CONN_FLAG_REQUEST_HEADERS_RECEIVED  = 0x02000000, /**< @brief All request headers received. Continue with request body. */
    CONN_FLAG_RESPONSE_STATUS_SENT      = 0x10000000, /**< @brief Response status line sent. */
    CONN_FLAG_RESPONSE_HEADERS_SENT     = 0x20000000, /**< @brief All response headers sent. Continue with response body. */
    CONN_FLAG_RESPONSE_BODY_SENT        = 0x40000000, /**< @brief Response body sent. Done. */

    CONN_FLAG_INTERNAL_MASK             = 0xFFFF0000  /**< @brief Mask for internal flags. */
};


/**
 * @brief WolfSSL custom verification callback.
 * @param[in] preverify Some flag from WolfSSL.
 * @param[in] store Verification context.
 * @return Zero if verification failed.
 */
static int http_conn_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
    // struct HTTP_Conn *conn = (struct HTTP_Conn*)store->userCtx;
    TRACE("enter http_client_verify_cb(%d, %p)\n", preverify, store);
    if (preverify)
    {
        INFO("SSL verification is OK (store:%p, userCtx:%p)\n",
             store, store->userCtx);
        return preverify;
    }

    int allowed = 0;

    DEBUG("SSL verification failed: (%d) %s\n",
          store->error, wolfSSL_ERR_reason_error_string(store->error));

    if (0)
    {
    WARN("SSL verification DISABLED!\n");
    allowed = 1;
    }

    #if 0 // OPENSSL_EXTRA
    WOLFSSL_X509* peer = store->current_cert;
    if (peer) {
        char* issuer  = CyaSSL_X509_NAME_oneline(
                                       CyaSSL_X509_get_issuer_name(peer), 0, 0);
        char* subject = CyaSSL_X509_NAME_oneline(
                                      CyaSSL_X509_get_subject_name(peer), 0, 0);
        printf("peer's cert info:\n issuer : %s\n subject: %s\n", issuer,
                                                                  subject);
        XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
        XFREE(issuer,  0, DYNAMIC_TYPE_OPENSSL);
    }
    else
        printf("peer has no cert!\n");
    #endif

    TRACE("leave http_client_verify_cb(%d)\n", allowed);
    return allowed;
}


/**
 * @brief Reset connection for next use.
 *
 * This function resets working buffer and all request/response related fields.
 *
 * @param[in] conn Connection to reset.
 */
static void http_conn_reset(struct HTTP_Conn *conn)
{
    // reset request
    conn->request.method = HTTP_UNKNOWN_METHOD;
    conn->request.protocol = HTTP_UNKNOWN_PROTO;
    http_conn_set_request_uri(conn, "", 0);
    http_conn_set_request_host(conn, "", 0);
    conn->request.headers.content_length = -1; // missing
    conn->request.headers.connection = HTTP_CONNECTION_MISSING;

    // reset response
    conn->response.protocol = HTTP_UNKNOWN_PROTO;
    conn->response.status = 0; // unknown
    http_conn_set_response_reason(conn, "", 0);
    conn->response.headers.content_length = -1; // missing
    conn->response.headers.connection = HTTP_CONNECTION_MISSING;

    // reset working buffer
    conn->internal.buf_pos = 0;
    conn->internal.buf_len = 0;

    // reset internal flags
    conn->internal.flags &= ~CONN_FLAG_INTERNAL_MASK;

    // nothing has been read
    conn->internal.content_pos = 0;
}


/**
 * @brief Check connection has flags set.
 * @param[in] conn Connection to check.
 * @param[in] flags Set of flags to check.
 * @return Non-zero if all flags are set.
 */
static inline int http_conn_has_flag(const struct HTTP_Conn *conn, uint32_t flags)
{
    return (conn->internal.flags & flags) == flags;
}


/**
 * @brief Set connection flags.
 * @param[in] conn Connection to set flags.
 * @param[in] flags Set of flags to set.
 */
static inline void http_conn_set_flag(struct HTTP_Conn *conn, uint32_t flags)
{
    // TODO: logging of flag changes
    conn->internal.flags |= flags;
}


/*
 * http_conn_new() implementation.
 */
int http_conn_new(WOLFSSL_CTX *ctx, int fd, struct HTTP_Conn **conn_)
{
    TRACE("enter http_conn_new(SSL_CTX_%p, socket_%d)\n", ctx, fd);

    // allocate memory
    struct HTTP_Conn *conn = (struct HTTP_Conn*)malloc(sizeof(*conn));
    if (!conn)
    {
        ERROR("http_conn_new(): FAILED to allocate %d bytes of memory: (%d) %s\n",
              (int)sizeof(*conn), errno, strerror(errno));
        return HTTP_ERR_NO_MEMORY; // failed
    }
    DEBUG("HttpConn_%p memory block of %d bytes allocated\n", conn, (int)sizeof(*conn));

    // default values
    conn->fd = -1;              // nothing
    conn->ssl = 0;              // nothing
    conn->remote_ipv4 = 0;      // unknown
    conn->remote_port = 0;      // unknown
    conn->request.uri = 0;      // use static buffer
    conn->request.host = 0;     // use static buffer
    conn->response.reason = 0;  // use static buffer
    http_conn_reset(conn);      // more defaults

    if (ctx) // is connection secure?
    {
        // create SSL stream
        conn->ssl = wolfSSL_new(ctx);
        if (!conn->ssl)
        {
            ERROR("HttpConn_%p FAILED to create SSL stream\n", conn);
            http_conn_free(conn);
            return HTTP_ERR_FAILED; // failed
        }
        DEBUG("HttpConn_%p SLL stream SSL_%p created\n", conn, conn->ssl);

        // bind socket and SSL stream
        const int err = wolfSSL_set_fd(conn->ssl, fd);
        if (WOLFSSL_SUCCESS != err)
        {
            ERROR("HttpConn_%p FAILED to set SSL socket: %d\n", conn, err);
            http_conn_free(conn);
            return HTTP_ERR_FAILED; // failed
        }

        // set custom verification callback
        wolfSSL_set_verify(conn->ssl, WOLFSSL_VERIFY_PEER,
                           http_conn_verify_cb);
        wolfSSL_SetCertCbCtx(conn->ssl, conn);
    }

    conn->fd = fd; // take care of socket!
    *conn_ = conn; // report new object
    TRACE("HttpConn_%p leave http_conn_new()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_free() implementation.
 */
void http_conn_free(struct HTTP_Conn *conn)
{
    TRACE("HttpConn_%p enter http_conn_free()\n", conn);

    if (!conn)
    {
        TRACE("nothing to release\n");
        return; // nothing to release
    }

    // release SSL stream
    if (conn->ssl)
    {
        while (1) // gracefully shutting down
        {
            DEBUG("HttpConn_%p shutting down SSL_%p\n",
                  conn, conn->ssl);
            const int err = wolfSSL_shutdown(conn->ssl);
            if (WOLFSSL_SUCCESS != err && WOLFSSL_ERROR_NONE != err)
            {
                if (WOLFSSL_SHUTDOWN_NOT_DONE == err)
                {
                    WARN("HttpConn_%p shutdown SSL_%p is NOT completed yet\n",
                         conn, conn->ssl);
                    continue; // try again, TODO: limit number of attempts?
                }

                ERROR("HttpConn_%p FAILED to shutdown SSL_%p: %d\n",
                      conn, conn->ssl, err);
            }
            else
            {
                INFO("HttpConn_%p shutdown SSL_%p is completed\n",
                     conn, conn->ssl);
            }

            break; // done
        }

        DEBUG("HttpConn_%p releasing SSL_%p\n",
              conn, conn->ssl);
        wolfSSL_free(conn->ssl);
        conn->ssl = 0;
    }

    // release socket
    if (conn->fd >= 0)
    {
        DEBUG("HttpConn_%p releasing underlying socket_%d\n",
              conn, conn->fd);
        misc_closesocket(conn->fd);
        conn->fd = -1;
    }

    // release URI dynamic buffer
    if (conn->request.uri)
    {
        DEBUG("HttpConn_%p releasing URI dynamic buffer\n", conn);
        free(conn->request.uri);
        conn->request.uri = 0;
    }

    // release HOST dynamic buffer
    if (conn->request.host)
    {
        DEBUG("HttpConn_%p releasing HOST dynamic buffer\n", conn);
        free(conn->request.host);
        conn->request.host = 0;
    }

    // release REASON dynamic buffer
    if (conn->response.reason)
    {
        DEBUG("HttpConn_%p releasing REASON dynamic buffer\n", conn);
        free(conn->response.reason);
        conn->response.reason = 0;
    }

    // release connection
    DEBUG("HttpConn_%p releasing...\n", conn);
    free(conn);

    TRACE("HttpConn_%p leave http_conn_free()\n", conn);
}


/*
 * http_conn_set_request_method() implementation.
 */
int http_conn_set_request_method(struct HTTP_Conn *conn, enum HTTP_Method method)
{
    if (conn->request.method != method)
    {
        if (HTTP_UNKNOWN_METHOD == conn->request.method)
        {
            DEBUG("HttpConn_%p set request method to \"%s\"\n",
                  conn, http_method_string(method));
        }
        else
        {
            DEBUG("HttpConn_%p change request method from \"%s\" to \"%s\"\n",
                  conn, http_method_string(conn->request.method),
                        http_method_string(method));
        }

        conn->request.method = method; // save
    }

    return HTTP_ERR_SUCCESS; // ok
}


/*
 * http_conn_set_request_proto() implementation.
 */
int http_conn_set_request_proto(struct HTTP_Conn *conn, enum HTTP_Proto proto)
{
    if (conn->request.protocol != proto)
    {
        if (HTTP_UNKNOWN_PROTO == conn->request.protocol)
        {
            DEBUG("HttpConn_%p set request protocol to \"%s\"\n",
                  conn, http_proto_string(proto));
        }
        else
        {
            DEBUG("HttpConn_%p change request protocol from \"%s\" to \"%s\"\n",
                  conn, http_proto_string(conn->request.protocol),
                        http_proto_string(proto));
        }

        conn->request.protocol = proto; // save
    }

    return HTTP_ERR_SUCCESS; // ok
}


/*
 * http_conn_set_request_uri() implementation.
 */
int http_conn_set_request_uri(struct HTTP_Conn *conn,
                              const char *uri,
                              int uri_len)
{
    if (uri_len < 0) // uri is NULL-terminated
    {
        TRACE("HttpConn_%p enter http_conn_set_request_uri(\"%s\", %d)\n",
              conn, uri, uri_len);
    }
    else
    {
        TRACE("HttpConn_%p enter http_conn_set_request_uri(\"%.*s\", %d)\n",
              conn, uri_len, uri, uri_len);
    }

    // release previous value if any
    if (conn->request.uri)
    {
        free(conn->request.uri);
        conn->request.uri = 0;
    }

    // update length if it's unknown
    if (uri_len < 0)
        uri_len = strlen(uri);

    // if 'fixed' buffer is large enough, use it
    if (uri_len < (int)sizeof(conn->request.uri_fixed))
    {
        memcpy(conn->request.uri_fixed, uri, uri_len);
        conn->request.uri_fixed[uri_len] = 0; // null-terminate
        conn->request.uri = 0; // use static buffer
        DEBUG("HttpConn_%p set URI=\"%s\" (use static buffer of %d bytes)\n",
              conn, http_conn_get_request_uri(conn), uri_len);
    }
    else // otherwise allocate dynamic buffer
    {
        conn->request.uri = (char*)malloc(uri_len+1);
        if (!conn->request.uri)
        {
            ERROR("HttpConn_%p FAILED to allocate %d bytes of memory to save URI: (%d) %s\n",
                  conn, uri_len+1, errno, strerror(errno));
            return HTTP_ERR_NO_MEMORY; // failed
        }

        memcpy(conn->request.uri, uri, uri_len);
        conn->request.uri[uri_len] = 0; // null-terminate
        conn->request.uri_fixed[0] = 0;
        DEBUG("HttpConn_%p set URI=\"%s\" (use dynamic buffer of %d bytes)\n",
              conn, http_conn_get_request_uri(conn), uri_len+1);
    }

    TRACE("HttpConn_%p leave http_conn_set_request_uri()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_add_request_uri() implementation.
 */
int http_conn_add_request_uri(struct HTTP_Conn *conn,
                              const char *uri_part)
{
    TRACE("HttpConn_%p enter http_conn_add_request_uri(\"%s\")\n", conn, uri_part);

    const int part_len = strlen(uri_part);
    // TODO: insert automatic path separator on 'ensure_separator' flag

    if (conn->request.uri) // dynamic buffer is used
    {
        const int old_len = strlen(conn->request.uri);
        char *uri = (char*)realloc(conn->request.uri, old_len+part_len+1);
        if (!uri)
        {
            ERROR("HttpConn_%p FAILED to re-allocate %d bytes of memory to save URI: (%d) %s\n",
                  conn, old_len+part_len+1, errno, strerror(errno));
            return HTTP_ERR_NO_MEMORY; // failed
        }

        memcpy(uri+old_len, uri_part, part_len+1); // also copy '\0'
        conn->request.uri = uri;

        DEBUG("HttpConn_%p update URI=\"%s\" (use dynamic buffer of %d bytes)\n",
              conn, http_conn_get_request_uri(conn), old_len+part_len+1);
    }
    else // 'fixed' buffer is used
    {
        const int old_len = strlen(conn->request.uri_fixed);
        if (old_len+part_len < (int)sizeof(conn->request.uri_fixed))
        {
            memcpy(conn->request.uri_fixed+old_len, uri_part, part_len+1); // also copy '\0'
            DEBUG("HttpConn_%p update URI=\"%s\" (use static buffer of %d bytes)\n",
                  conn, http_conn_get_request_uri(conn), old_len+part_len);
        }
        else // otherwise allocate dynamic buffer
        {
            conn->request.uri = (char*)malloc(old_len+part_len+1);
            if (!conn->request.uri)
            {
                ERROR("HttpConn_%p FAILED to allocate %d bytes of memory to save URI: (%d) %s\n",
                      conn, old_len+part_len+1, errno, strerror(errno));
                return HTTP_ERR_NO_MEMORY; // failed
            }

            memcpy(conn->request.uri, conn->request.uri_fixed, old_len);
            memcpy(conn->request.uri+old_len, uri_part, part_len+1); // also copy '\0'
            conn->request.uri_fixed[0] = 0;
        }
    }

    TRACE("HttpConn_%p leave http_conn_add_request_uri()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_set_request_host() implementation.
 */
int http_conn_set_request_host(struct HTTP_Conn *conn,
                               const char *host,
                               int host_len)
{
    TRACE("HttpConn_%p enter http_conn_set_request_host(\"%.*s\", %d)\n",
          conn, host_len, host, host_len);

    // release previous value if any
    if (conn->request.host)
    {
        free(conn->request.host);
        conn->request.host = 0;
    }

    // update length if it's unknown
    if (host_len < 0)
        host_len = strlen(host);

    // if 'fixed' buffer is large enough, use it
    if (host_len < (int)sizeof(conn->request.host_fixed))
    {
        memcpy(conn->request.host_fixed, host, host_len);
        conn->request.host_fixed[host_len] = 0; // null-terminate
        conn->request.host = 0; // use static buffer
        DEBUG("HttpConn_%p set HOST=\"%s\" (use static buffer of %d bytes)\n",
              conn, http_conn_get_request_host(conn), host_len);
    }
    else // otherwise allocate dynamic buffer
    {
        conn->request.host = (char*)malloc(host_len+1);
        if (!conn->request.host)
        {
            ERROR("HttpConn_%p FAILED to allocate %d bytes of memory to save HOST: (%d) %s\n",
                  conn, host_len+1, errno, strerror(errno));
            return HTTP_ERR_NO_MEMORY; // failed
        }

        memcpy(conn->request.host, host, host_len);
        conn->request.host[host_len] = 0; // null-terminate
        conn->request.host_fixed[0] = 0;
        DEBUG("HttpConn_%p set HOST=\"%s\" (use dynamic buffer of %d bytes)\n",
              conn, http_conn_get_request_host(conn), host_len+1);
    }

    TRACE("HttpConn_%p leave http_conn_set_request_host()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_set_response_proto() implementation.
 */
int http_conn_set_response_proto(struct HTTP_Conn *conn, enum HTTP_Proto proto)
{
    if (conn->response.protocol != proto)
    {
        if (HTTP_UNKNOWN_PROTO == conn->response.protocol)
        {
            DEBUG("HttpConn_%p set response protocol to \"%s\"\n",
                  conn, http_proto_string(proto));
        }
        else
        {
            DEBUG("HttpConn_%p change response protocol from \"%s\" to \"%s\"\n",
                  conn, http_proto_string(conn->response.protocol),
                        http_proto_string(proto));
        }

        conn->response.protocol = proto; // save
    }

    return HTTP_ERR_SUCCESS; // ok
}


/*
 * http_conn_set_response_status() implementation.
 */
int http_conn_set_response_status(struct HTTP_Conn *conn, int status)
{
    if (conn->response.status != status)
    {
        if (0 == conn->response.status) // is unknown
        {
            DEBUG("HttpConn_%p set response status to %d\n",
                  conn, status);
        }
        else
        {
            DEBUG("HttpConn_%p change response status from %d to %d\n",
                  conn, conn->response.status, status);
        }

        conn->response.status = status; // save
    }

    return HTTP_ERR_SUCCESS; // ok
}


/*
 * http_conn_set_response_reason() implementation.
 */
int http_conn_set_response_reason(struct HTTP_Conn *conn,
                                  const char *reason,
                                  int reason_len)
{
    if (reason_len < 0) // NULL-terminated
    {
        TRACE("HttpConn_%p enter http_conn_set_response_reason(\"%s\", %d)\n",
              conn, reason, reason_len);
    }
    else
    {
        TRACE("HttpConn_%p enter http_conn_set_response_reason(\"%.*s\", %d)\n",
              conn, reason_len, reason, reason_len);
    }

    // release previous value if any
    if (conn->response.reason)
    {
        free(conn->response.reason);
        conn->response.reason = 0;
    }

    // update length if it's unknown
    if (reason_len < 0)
        reason_len = strlen(reason);

    // if 'fixed' buffer is large enough, use it
    if (reason_len < (int)sizeof(conn->response.reason_fixed))
    {
        memcpy(conn->response.reason_fixed, reason, reason_len);
        conn->response.reason_fixed[reason_len] = 0; // null-terminate
        conn->response.reason = 0; // use static buffer
        DEBUG("HttpConn_%p set REASON=\"%s\" (use static buffer of %d bytes)\n",
              conn, http_conn_get_response_reason(conn), reason_len);
    }
    else // otherwise allocate dynamic buffer
    {
        conn->response.reason = (char*)malloc(reason_len+1);
        if (!conn->response.reason)
        {
            ERROR("HttpConn_%p FAILED to allocate %d bytes of memory to save REASON: (%d) %s\n",
                  conn, reason_len+1, errno, strerror(errno));
            return HTTP_ERR_NO_MEMORY; // failed
        }

        memcpy(conn->response.reason, reason, reason_len);
        conn->response.reason[reason_len] = 0; // null-terminate
        conn->response.reason_fixed[0] = 0;
        DEBUG("HttpConn_%p set REASON=\"%s\" (use dynamic buffer of %d bytes)\n",
              conn, http_conn_get_response_reason(conn), reason_len+1);
    }

    TRACE("HttpConn_%p leave http_conn_set_response_reason()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Send some output data directly to underying socket.
 *
 * No any buffers are used here.
 *
 * @param[in] conn Connection to send data to.
 * @param[in] buf Data buffer.
 * @param[in,out] len Data buffer size in bytes on input.
 *                    Actual number of bytes sent on output.
 * @return Zero on success.
 */
static int http_conn_send_some(struct HTTP_Conn *conn, const void *buf, int *len)
{
    TRACE("HttpConn_%p enter http_conn_send_some(%p, %d)\n", conn, buf, *len);

    if (conn->ssl) // use secure connection
    {
        const int err = wolfSSL_send(conn->ssl, buf, *len, 0);
        if (err < 0)
        {
            const int ssl_err = wolfSSL_get_error(conn->ssl, err);
            ERROR("HttpConn_%p FAILED to send %d bytes: (%d) %s\n", conn,
                  *len, ssl_err, wolfSSL_ERR_reason_error_string(ssl_err));
            return HTTP_ERR_WRITE; // failed
        }

        DEBUG("HttpConn_%p send %d of %d bytes to SSL_%p stream\n",
              conn, err, *len, conn->ssl);
        *len = err; // report actual size!
    }
    else // use plain http connection
    {
        const int err = send(conn->fd, (void*)buf, *len, 0);
        if (err < 0)
        {
            ERROR("HttpConn_%p FAILED to send %d bytes: (%d) %s\n",
                  conn, *len, errno, strerror(errno));
            return HTTP_ERR_WRITE; // failed
        }

        DEBUG("HttpConn_%p send %d of %d bytes to socket_%d\n",
              conn, err, *len, conn->fd);
        *len = err; // report actual size!
    }

    TRACE("HttpConn_%p leave http_conn_send_some(%d)\n", conn, *len);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Send all output data directly to underying socket.
 *
 * No any buffers are used here.
 *
 * @param conn Connection to send data to.
 * @param buf Data buffer.
 * @param len Data buffer size in bytes.
 * @return Zero on success.
 */
static int http_conn_send_all(struct HTTP_Conn *conn, const void *buf, int len)
{
    TRACE("HttpConn_%p enter http_conn_send_all(%p, %d)\n", conn, buf, len);

    // do a few iterations...
    while (len > 0)
    {
        int n = len; // data length on this iteration
        const int err = http_conn_send_some(conn, buf, &n);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
        if (!n) // no data sent
        {
            // TODO: do we need to wait a bit and try again?
            ERROR("HttpConn_%p not ALL data sent: %d bytes remain\n", conn, len);
            return HTTP_ERR_WRITE; // failed
        }

        buf = (const uint8_t*)buf + n;
        len -= n;
    }

    TRACE("HttpConn_%p leave http_conn_send_all()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Send output data (buffered).
 *
 * Internal buffer is used first.
 *
 * @param[in] conn Connection to send data to.
 * @param[in] buf Data buffer.
 * @param[in] len Data buffer size in bytes.
 * @return Zero on success.
 */
static int http_conn_send(struct HTTP_Conn *conn, const void *buf, int len)
{
    TRACE("HttpConn_%p enter http_conn_send(%p, %d)\n", conn, buf, len);
    struct HTTP_ConnInternal *ci = &conn->internal;

    // try to put data to working buffer
    int space = HTTP_CONN_BUF_SIZE - ci->buf_len;
    if (space >= len) // or just (space > 0)?
    {
        // enough space to save full buffer
        memcpy(ci->buf + ci->buf_len, buf, len);
        ci->buf_len += len;

        DEBUG("HttpConn_%p %d bytes buffered, buffer{pos:%d, len:%d}\n",
              conn, len, ci->buf_pos, ci->buf_len);

        buf = (const uint8_t*)buf + len;
        space -= len;
        len -= len;
    }

    // flush working buffer
    if (space == 0 || (len > 0 && ci->buf_len > 0))
    {
        DEBUG("HttpConn_%p sending working buffer of %d bytes...\n", conn, ci->buf_len);
        const int err = http_conn_send_all(conn, ci->buf, ci->buf_len);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
        ci->buf_len = 0; // buffer is empty now
    }

    // send remaining data (chunk by chunk)
    while (len >= HTTP_CONN_BUF_SIZE)
    {
        const int n = (len >= HTTP_CONN_BUF_SIZE) ? HTTP_CONN_BUF_SIZE : len;
        DEBUG("HttpConn_%p sending user buffer of %d bytes...\n", conn, n);
        const int err = http_conn_send_all(conn, buf, n);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
        buf = (const uint8_t*)buf + n;
        len -= n;
    }

    // put remaining data to working buffer
    if (len > 0)
    {
        memcpy(ci->buf + ci->buf_len, buf, len);
        ci->buf_len += len;

        DEBUG("HttpConn_%p remaining %d bytes buffered, buffer{pos:%d, len:%d}\n",
              conn, len, ci->buf_pos, ci->buf_len);

        buf = (const uint8_t*)buf + len;
        len -= len;
    }

    TRACE("HttpConn_%p leave http_conn_send()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Receive some input data directly from underying socket.
 *
 * No any buffers are used here.
 *
 * @param[in] conn Connection to receive data from.
 * @param[in] buf Data buffer.
 * @param[in,out] len Data buffer size in bytes on input.
 *                    Actual number of bytes read on output.
 * @return Zero on success.
 */
static int http_conn_recv_some(struct HTTP_Conn *conn, void *buf, int *len)
{
    TRACE("HttpConn_%p enter http_conn_recv_some(%p, %d)\n", conn, buf, *len);

    if (conn->ssl) // use secure connection
    {
        const int err = wolfSSL_recv(conn->ssl, buf, *len, 0);
        if (err < 0)
        {
            const int ssl_err = wolfSSL_get_error(conn->ssl, err);
            ERROR("HttpConn_%p FAILED to receive: (%d) %s\n", conn,
                  ssl_err, wolfSSL_ERR_reason_error_string(ssl_err));
            return HTTP_ERR_READ; // failed
        }

        DEBUG("HttpConn_%p receive %d of %d bytes from SSL_%p stream\n",
              conn, err, *len, conn->ssl);
        *len = err; // report actual size!
    }
    else // use plain http connection
    {
        const int err = recv(conn->fd, buf, *len, 0);
        if (err < 0)
        {
            ERROR("HttpConn_%p FAILED to receive: (%d) %s\n",
                  conn, errno, strerror(errno));
            return HTTP_ERR_READ; // failed
        }

        DEBUG("HttpConn_%p receive %d of %d bytes from socket_%d\n",
              conn, err, *len, conn->fd);
        *len = err; // report actual size!
    }

    TRACE("HttpConn_%p leave http_conn_recv_some(%d)\n", conn, *len);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Grow working buffer by receiving some data.
 * @param[in] conn Connection to grow buffer of.
 * @return Zero on success.
 */
static int http_conn_wbuf_grow(struct HTTP_Conn *conn)
{
    TRACE("HttpConn_%p enter http_conn_wbuf_grow()\n", conn);
    struct HTTP_ConnInternal *ci = &conn->internal;

    int space = HTTP_CONN_BUF_SIZE - ci->buf_len;
    if (!space)
    {
        ERROR("HttpConn_%p no more space to receive data\n", conn);
        return HTTP_ERR_ILLEGAL;
    }

    // read some data to the end of working buffer
    const int err = http_conn_recv_some(conn, ci->buf + ci->buf_len, &space);
    if (HTTP_ERR_SUCCESS != err)
        return err; // failed
    if (!space)
    {
        // TODO: wait a bit and try again?
        ERROR("HttpConn_%p no data received\n", conn);
        return HTTP_ERR_READ;
    }

    ci->buf_len += space;
    DEBUG("HttpConn_%p receive %d bytes into working buffer, buffer{pos:%d, len:%d}\n",
          conn, space, ci->buf_pos, ci->buf_len);

    TRACE("HttpConn_%p leave http_conn_wbuf_grow()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Shrink working buffer.
 * @param[in] conn Connection to shrink working buffer of.
 * @return Zero on success.
 */
static int http_conn_wbuf_shrink(struct HTTP_Conn *conn)
{
    TRACE("HttpConn_%p enter http_conn_wbuf_shrink()\n", conn);
    struct HTTP_ConnInternal *ci = &conn->internal;

    if (!ci->buf_pos)
    {
        TRACE("nothing to shrink\n");
        return HTTP_ERR_SUCCESS; // OK
    }

    // check remaining data
    const int rem = ci->buf_len - ci->buf_pos;
    if (rem > 0)
    {
        // move remaining bytes to the begin of buffer
        memmove(ci->buf, ci->buf + ci->buf_pos, rem);
        ci->buf_len = rem;
        ci->buf_pos = 0;

        DEBUG("HttpConn_%p rewind %d bytes of working buffer, buffer{pos:%d, len:%d}\n",
              conn, rem, ci->buf_pos, ci->buf_len);
    }
    else
    {
        ci->buf_len = 0;
        ci->buf_pos = 0;
    }

    TRACE("HttpConn_%p leave http_conn_wbuf_shrink()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Parse HTTP header line.
 * @param[in] line Begin of HEADER line.
 *                 Should be NULL-terminated.
 * @param[in] len Length of HEADER line in bytes.
 * @param[out] name Header name.
 * @param[out] value Header value.
 * @return Zero on success.
 */
static int http_parse_header_line(char *line, int len,
                                  const char **name,
                                  const char **value)
{
    //TRACE("enter http_parse_header_line(\"%.*s\", %d)\n", len, line, len);

    char *colon = (char*)memchr(line, ':', len);
    if (colon)
    {
        if (name) *name = line;
        *colon = 0; // NULL-terminate 'name'

        colon += 1; // skip ':'
        // skip spaces in the value
        while (*colon && *colon == ' ')
            colon += 1;

        if (value) *value = colon;
    }
    else
    {
        ERROR("http_parse_header_line(): bad HEADER line \"%.*s\": %s\n",
              len, line, "no colon found");
        return HTTP_ERR_BAD_HEADER_NO_COLON;
    }

    //TRACE("leave http_parse_header_line()\n");
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Send custom HTTP header helper.
 *
 * Header name and it's value will be written to internal buffer.
 * If there is no available space in the buffer then
 * buffer will be sent to the underlying socket first.
 *
 * @param[in] conn Connection to send header to.
 * @param[in] name Header name.
 * @param[in] value Header value.
 * @return Zero on success.
 *
 * @see http_conn_send_request_header()
 * @see http_conn_send_response_header()
 */
static int http_conn_send_header(struct HTTP_Conn *conn,
                                 const char *name,
                                 const char *value)
{
    TRACE("HttpConn_%p enter http_conn_send_header(\"%s\", \"%s\")\n", conn, name, value);
    struct HTTP_ConnInternal *ci = &conn->internal;

    while (1) // at most two iterations
    {
        // try to put "header: value" to the end of internal buffer
        const int space = HTTP_CONN_BUF_SIZE - ci->buf_len;
        const int err = snprintf((char*)&ci->buf[ci->buf_len], space,
                                 "%s: %s\r\n", name, value);
        if (err < 0)
        {
            ERROR("HttpConn_%p failed to format header: (%d) %s\n",
                  conn, errno, strerror(errno));
            return HTTP_ERR_FAILED; // failed
        }
        else if (err >= space)
        {
            // in some rare cases the header line
            // could be too big to fit working buffer
            if (space == HTTP_CONN_BUF_SIZE)
            {
                ERROR("HttpConn_%p failed to send header: %s\n",
                      conn, "too long to fit internal buffer");
                return HTTP_ERR_FAILED; // failed
            }

            // buffer is overflow!
            DEBUG("HttpConn_%p sending working buffer of %d bytes...\n", conn, ci->buf_len);
            const int err = http_conn_send_all(conn, ci->buf, ci->buf_len);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
            ci->buf_len = 0; // buffer is empty now
            continue; // try again with empty buffer...
        }

        ci->buf_len += err;
        break; // done
    }

    TRACE("HttpConn_%p leave http_conn_send_header()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Receive custom HTTP header helper.
 *
 * If there is no more HTTP header in the request, then
 * both name and value are set to `NULL`.
 *
 * @param[in] conn Connection to receive HTTP header from.
 * @param[out] name Header name.
 * @param[out] value Header value.
 * @return Zero on success.
 */
static int http_conn_recv_header(struct HTTP_Conn *conn,
                                 const char **name,
                                 const char **value)
{
    TRACE("HttpConn_%p enter http_conn_recv_header()\n", conn);
    struct HTTP_ConnInternal *ci = &conn->internal;

    int attempt = 0;
    while (1) // read header line
    {
        // usually do not grow buffer on first iteration
        // grow it only if there is no data in working buffer
        if (attempt || (ci->buf_len - ci->buf_pos) <= 0)
        {
            // do we have space in working buffer?
            if (HTTP_CONN_BUF_SIZE - ci->buf_len > 0)
            {
                // getting some data into working buffer
                DEBUG("HttpConn_%p growing working buffer (attempt:%d)...\n",
                      conn, attempt);
                const int err = http_conn_wbuf_grow(conn);
                if (HTTP_ERR_SUCCESS != err)
                    return err; // failed
            }
            else
            {
                ERROR("HttpConn_%p header line too big to fit working buffer\n", conn);
                return HTTP_ERR_FAILED; // failed
            }
        }

        // check the whole line received
        uint8_t *line_beg = ci->buf + ci->buf_pos;
        const uint8_t *line_end = (const uint8_t*)http_find_crlf(line_beg,
                                               ci->buf_len - ci->buf_pos);
        if (!line_end)
        {
            // have to shrink buffer?
            if (ci->buf_len >= HTTP_CONN_BUF_SIZE)
            {
                DEBUG("HttpConn_%p working buffer is full, shrinking...\n", conn);
                const int err = http_conn_wbuf_shrink(conn);
                if (HTTP_ERR_SUCCESS != err)
                    return err;
            }

            attempt += 1;
            continue; // need more data
        }

        const int line_len = (line_end - line_beg);
        if (line_len)
        {
            // parse header line
            line_beg[line_len] = 0; // NULL-terminate for logging purpose
            const int err = http_parse_header_line((char*)line_beg, line_len,
                                                   name, value);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
        }

        ci->buf_pos += line_len + 2; // + "\r\n"
        break; // done
    }

    TRACE("HttpConn_%p leave http_conn_recv_header()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Receive HTTP body helper.
 * @param[in] conn Connection to receive data from.
 * @param[in] buf Buffer to store received data.
 * @param[in,out] len Buffer length in bytes on input.
 *                    Actual number of bytes read on output.
 * @return Zero on success.
 */
static int http_conn_recv_body(struct HTTP_Conn *conn,
                               void *buf, int *len_)
{
    TRACE("HttpConn_%p enter http_conn_recv_body(%p, %d)\n", conn, buf, *len_);
    struct HTTP_ConnInternal *ci = &conn->internal;

    int total_read = 0;
    int len = *len_;

    // first, copy data from internal buffer
    const int buf_len = ci->buf_len - ci->buf_pos;
    if (len > 0 && buf_len > 0)
    {
        const int n = (len < buf_len) ? len : buf_len;
        memcpy(buf, ci->buf + ci->buf_pos, n);
        ci->buf_pos += n;
        DEBUG("HttpConn_%p copy %d bytes from working buffer{pos:%d, len:%d}\n",
              conn, n, ci->buf_pos, ci->buf_len);

        buf = (uint8_t*)buf + n;
        total_read += n;
        len -= n;

        // shrink working buffer if it's full and all data read
        if (ci->buf_pos >= HTTP_CONN_BUF_SIZE)
        {
            DEBUG("HttpConn_%p shrink working buffer...\n", conn);
            const int err = http_conn_wbuf_shrink(conn);
            if (HTTP_ERR_SUCCESS != err)
                return err;
        }
    }

    // read remaining data directly from socket
    while (len > 0) // TODO: read HTTP_CONN_BUF_SIZE chunk
    {
        int n = len;
        const int err = http_conn_recv_some(conn, buf, &n);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
        if (!n) // no data read
        {
            // TODO: wait a bit and try again?
            ERROR("HttpConn_%p not all data received: %d bytes remain\n", conn, len);
            return HTTP_ERR_READ; // failed
        }
        buf = (uint8_t*)buf + n;
        total_read += n;
        len -= n;
    }

    // TODO: grow working buffer and fill rest of data?

    *len_ = total_read; // report actual size!
    TRACE("HttpConn_%p leave http_conn_recv_body(%d)\n", conn, *len_);
    return HTTP_ERR_SUCCESS; // OK
}


// HTTP connection - client related
#if defined(HTTP_CLIENT)

/**
 * @brief Parse HTTP response status line.
 * @param[in] conn Connection to parse response status line of.
 * @param[in] line Begin of response status line.
 *                 Should be NULL-terminated for logging purposes.
 * @param[in] len Length of response status line in bytes.
 * @return Zero on success.
 */
static int http_conn_parse_response_status(struct HTTP_Conn *conn, uint8_t *line, int len)
{
    TRACE("HttpConn_%p enter http_conn_parse_response_status(\"%.*s\", %d)\n", conn, len, line, len);

    // parse HTTP protocol
    enum HTTP_Proto proto = HTTP_UNKNOWN_PROTO;
    uint8_t *proto_end = (uint8_t*)memchr(line, ' ', len);
    if (proto_end)
    {
        const int proto_len = proto_end - line;
        *proto_end = 0; // NULL-terminate the protocol
        if (proto_len == 8 && 0 == memcmp(line, "HTTP/1.0", 8))
            proto = HTTP_PROTO_1_0;
        else if (proto_len == 8 && 0 == memcmp(line, "HTTP/1.1", 8))
            proto = HTTP_PROTO_1_1;
        else
        {
            WARN("HttpConn_%p unknown HTTP protocol \"%.*s\" found, ignored\n",
                 conn, proto_len, line);
            // try to continue with unknown HTTP protocol...
        }

        line += proto_len + 1; // skip space
        len -= proto_len + 1;  // skip space
    }
    else
    {
        ERROR("HttpConn_%p bad RESPONSE status: %s\n", conn, "no HTTP protocol found");
        return HTTP_ERR_BAD_RESPONSE_NO_PROTOCOL; // failed
    }

    // parse status code
    char *status_end = 0;
    const int status = strtol((const char*)line, &status_end, 10);
    if (!status_end || status_end == (char*)line)
    {
        ERROR("HttpConn_%p bad RESPONSE status: %s\n", conn, "no status code found");
        return HTTP_ERR_BAD_RESPONSE_NO_STATUS; // failed
    }
    // TODO: check status range if (status <= 0 || status >= 1000)
    len -= status_end - (char*)line;
    line = (uint8_t*)status_end;

    // skip spaces
    while (len > 0 && *line == ' ')
    {
        line += 1;
        len -= 1;
    }

    // TODO: check reason is not empty

    // save all parsed values
    http_conn_set_response_status(conn, status);
    http_conn_set_response_proto(conn, proto);
    const int err = http_conn_set_response_reason(conn, (const char*)line, len);
    if (HTTP_ERR_SUCCESS != err)
        return err; // failed

    TRACE("HttpConn_%p leave http_conn_parse_response_status()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_send_request_line() implementation.
 */
int http_conn_send_request_line(struct HTTP_Conn *conn)
// see http_conn_send_response_status() for the almost the same implmentation
{
    TRACE("HttpConn_%p enter http_conn_send_request_line()\n", conn);
    struct HTTP_ConnInternal *ci = &conn->internal;

    // can we send request line?
    if (http_conn_has_flag(conn, CONN_FLAG_REQUEST_LINE_SENT))
    {
        ERROR("HttpConn_%p request line already sent\n", conn);
        return HTTP_ERR_ILLEGAL; // failed
    }

    while (1) // at most two iterations
    {
        // try to put METHOD URI PROTOCOL to the end of internal buffer
        const int space = HTTP_CONN_BUF_SIZE - ci->buf_len;
        const int err = snprintf((char*)&ci->buf[ci->buf_len], space,
                                 "%s %s %s\r\n",
                                 http_conn_get_request_method(conn),
                                 http_conn_get_request_uri(conn),
                                 http_conn_get_request_proto(conn));
        if (err < 0)
        {
            ERROR("HttpConn_%p failed to format request line: (%d) %s\n",
                  conn, errno, strerror(errno));
            return HTTP_ERR_FAILED; // failed
        }
        else if (err >= space)
        {
            // in some rare cases the request line
            // could be too big to fit working buffer
            if (space == HTTP_CONN_BUF_SIZE)
            {
                ERROR("HttpConn_%p failed to send request line: %s\n",
                      conn, "too long to fit internal buffer");
                return HTTP_ERR_FAILED; // failed
            }

            // buffer is overflow!
            DEBUG("HttpConn_%p sending working buffer of %d bytes...\n", conn, ci->buf_len);
            const int err = http_conn_send_all(conn, ci->buf, ci->buf_len);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
            ci->buf_len = 0; // buffer is empty now
            continue; // try again with empty buffer...
        }

        ci->buf_len += err;
        break; // done
    }

    http_conn_set_flag(conn, CONN_FLAG_REQUEST_LINE_SENT);
    INFO("HttpConn_%p request line \"%s %s %s\" buffered\n", conn,
          http_conn_get_request_method(conn),
          http_conn_get_request_uri(conn),
          http_conn_get_request_proto(conn));
    DEBUG("HttpConn_%p internal buffer{pos:%d, len:%d}\n",
          conn, ci->buf_pos, ci->buf_len);

    TRACE("HttpConn_%p leave http_conn_send_request_line()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_send_request_header() implementation.
 */
int http_conn_send_request_header(struct HTTP_Conn *conn,
                                  const char *name,
                                  const char *value)
// see http_conn_send_response_header() for the almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_send_request_header(\"%s\", \"%s\")\n", conn, name, value);
    struct HTTP_ConnInternal *ci = &conn->internal;

    // can we send header?
    if (http_conn_has_flag(conn, CONN_FLAG_REQUEST_HEADERS_SENT))
    {
        ERROR("HttpConn_%p all request headers already sent\n", conn);
        return HTTP_ERR_ILLEGAL; // failed
    }

    // have to send request line first
    if (!http_conn_has_flag(conn, CONN_FLAG_REQUEST_LINE_SENT))
    {
        // send request line METHOD URI PROTOCOL
        DEBUG("HttpConn_%p sending request line...\n", conn);
        const int err = http_conn_send_request_line(conn);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    // send header via helper
    const int err = http_conn_send_header(conn, name, value);
    if (HTTP_ERR_SUCCESS != err)
        return err;

    // check if "Host" header is sent
    if (0 == strcmp(name, "Host"))
    {
        http_conn_set_flag(conn, CONN_FLAG_REQUEST_HOST_HEADER_SENT);
    }
    INFO("HttpConn_%p request header \"%s: %s\" buffered\n", conn, name, value);
    DEBUG("HttpConn_%p internal buffer{pos:%d, len:%d}\n",
          conn, ci->buf_pos, ci->buf_len);

    TRACE("HttpConn_%p leave http_conn_send_request_header()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_send_request_body() implementation.
 */
int http_conn_send_request_body(struct HTTP_Conn *conn,
                                const void *buf, int len)
// see http_conn_send_response_body() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_send_request_body(%p, %d)\n", conn, buf, len);
    struct HTTP_ConnInternal *ci = &conn->internal;

    // can we send body?
    if (http_conn_has_flag(conn, CONN_FLAG_REQUEST_BODY_SENT))
    {
        ERROR("HttpConn_%p request body already sent\n", conn);
        return HTTP_ERR_ILLEGAL; // failed
    }

    // have to finish all headers
    if (!http_conn_has_flag(conn, CONN_FLAG_REQUEST_HEADERS_SENT))
    {
        // have to send Host header or request line
        if (!http_conn_has_flag(conn, CONN_FLAG_REQUEST_HOST_HEADER_SENT))
        {
            // send automatic "Host" header (if not send manually before)
            DEBUG("HttpConn_%p sending automatic \"%s\" header...\n", conn, "Host");
            const int err = http_conn_send_request_header(conn, "Host", http_conn_get_request_host(conn));
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
        }
        else if (!http_conn_has_flag(conn, CONN_FLAG_REQUEST_LINE_SENT))
        {
            // send request line "METHOD URI PROTOCOL"
            DEBUG("HttpConn_%p sending request line...\n", conn);
            const int err = http_conn_send_request_line(conn);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
        }

        // write empty line - "headers end" marker
        DEBUG("HttpConn_%p sending EMPTY line...\n", conn);
        const int err = http_conn_send(conn, "\r\n", 2);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed

        http_conn_set_flag(conn, CONN_FLAG_REQUEST_HEADERS_SENT); // headers sent
        INFO("HttpConn_%p ALL request headers buffered\n", conn);
        DEBUG("HttpConn_%p internal buffer{pos:%d, len:%d}\n",
              conn, ci->buf_pos, ci->buf_len);
    }

    if (len > 0)
    {
        // write data to buffer
        DEBUG("HttpConn_%p sending %d bytes of data...\n", conn, len);
        const int err = http_conn_send(conn, buf, len);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    TRACE("HttpConn_%p leave http_conn_send_request_body()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_flush_request() implementation.
 */
int http_conn_flush_request(struct HTTP_Conn *conn)
// see http_conn_flush_response() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_flush_request()\n", conn);
    struct HTTP_ConnInternal *ci = &conn->internal;

    // have to flush?
    if (http_conn_has_flag(conn, CONN_FLAG_REQUEST_BODY_SENT))
    {
        TRACE("HttpConn_%p request already finished\n", conn);
        return HTTP_ERR_SUCCESS; // still OK
    }

    // write empty body part (will write request line and all headers)
    const int err = http_conn_send_request_body(conn, "", 0);
    if (HTTP_ERR_SUCCESS != err)
        return err; // failed

    // flush buffer
    if (ci->buf_len > 0)
    {
        DEBUG("HttpConn_%p sending working buffer of %d bytes...\n", conn, ci->buf_len);
        const int err = http_conn_send_all(conn, ci->buf, ci->buf_len);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
        ci->buf_len = 0; // buffer is empty now
    }

    http_conn_set_flag(conn, CONN_FLAG_REQUEST_BODY_SENT); // body sent
    INFO("HttpConn_%p FULL request sent\n", conn);
    DEBUG("HttpConn_%p internal buffer{pos:%d, len:%d}\n",
          conn, ci->buf_pos, ci->buf_len);

    TRACE("HttpConn_%p leave http_conn_flush_request()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_recv_response_status() implementation.
 */
int http_conn_recv_response_status(struct HTTP_Conn *conn)
// see http_conn_recv_request_line() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_recv_response_status()\n", conn);
    struct HTTP_ConnInternal *ci = &conn->internal;

    // have to finish request sending?
    if (!http_conn_has_flag(conn, CONN_FLAG_REQUEST_BODY_SENT))
    {
        DEBUG("HttpConn_%p finishing request...\n", conn);
        const int err = http_conn_flush_request(conn);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    // have to receive response status line?
    if (http_conn_has_flag(conn, CONN_FLAG_RESPONSE_STATUS_RECEIVED))
    {
        TRACE("HttpConn_%p response status line already received\n", conn);
        return HTTP_ERR_SUCCESS; // OK
    }

    // response sent, reset the working buffer
    ci->buf_pos = 0;
    ci->buf_len = 0;
    DEBUG("HttpConn_%p reset working buffer{pos:%d, len:%d}\n",
          conn, ci->buf_pos, ci->buf_len);

    while (1) // read response status line
    {
        // do we have space in working buffer?
        if (HTTP_CONN_BUF_SIZE - ci->buf_len > 0)
        {
            // getting some data into working buffer
            const int err = http_conn_wbuf_grow(conn);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
        }
        else
        {
            ERROR("HttpConn_%p response status line too big to fit working buffer\n", conn);
            return HTTP_ERR_FAILED; // failed
        }

        // check the whole line received
        uint8_t *line_beg = ci->buf + ci->buf_pos;
        const uint8_t *line_end = (const uint8_t*)http_find_crlf(line_beg,
                                               ci->buf_len - ci->buf_pos);
        if (!line_end)
            continue; // need more data

        const int line_len = line_end - line_beg;
        if (!line_len)
        {
            ERROR("HttpConn_%p empty response status line received\n", conn);
            http_conn_set_flag(conn, CONN_FLAG_RESPONSE_HEADERS_RECEIVED);
            return HTTP_ERR_FAILED; // failed
        }

        // parse response status line
        line_beg[line_len] = 0; // NULL-terminate for logging purposes
        const int err = http_conn_parse_response_status(conn, line_beg, line_len);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed

        ci->buf_pos += line_len + 2; // + "\r\n"
        break; // done
    }

    // mark response status line as received
    http_conn_set_flag(conn, CONN_FLAG_RESPONSE_STATUS_RECEIVED);
    INFO("HttpConn_%p response status line \"%s %d %s\" received\n",
         conn, http_conn_get_response_proto(conn),
         http_conn_get_response_status(conn),
         http_conn_get_response_reason(conn));

    TRACE("HttpConn_%p leave http_conn_recv_response_status()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_recv_response_header() implementation.
 */
int http_conn_recv_response_header(struct HTTP_Conn *conn,
                                   const char **name,
                                   const char **value)
// see http_conn_recv_request_header() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_recv_response_header()\n", conn);

    // can we receive more headers?
    if (http_conn_has_flag(conn, CONN_FLAG_RESPONSE_HEADERS_RECEIVED))
    {
        ERROR("HttpConn_%p all headers already received\n", conn);
        return HTTP_ERR_ILLEGAL;
    }

    // have we receive response status line?
    if (!http_conn_has_flag(conn, CONN_FLAG_RESPONSE_STATUS_RECEIVED))
    {
        DEBUG("HttpConn_%p try to receive response status line...\n", conn);
        const int err = http_conn_recv_response_status(conn);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    const char *h_name = 0;
    const char *h_value = 0;
    const int err = http_conn_recv_header(conn, &h_name, &h_value);
    if (HTTP_ERR_SUCCESS != err)
        return err; // failed
    if (h_name && h_value)
    {
        INFO("HttpConn_%p response header \"%s: %s\" received\n",
             conn, h_name, h_value);
    }
    else
    {
        INFO("HttpConn_%p EMPTY line received - end of response headers\n", conn);
        http_conn_set_flag(conn, CONN_FLAG_RESPONSE_HEADERS_RECEIVED); // can receive body now
    }

    // handle common headers
    if (h_name && h_value)
    {
        // check "Content-Length" header
        if (0 == strcmp(h_name, "Content-Length"))
        {
            conn->response.headers.content_length = strtoll(h_value, 0, 10);
            // TODO: check extra data and the end of value?
            INFO("HttpConn_%p response content length parsed as %lld\n",
                 conn, (long long int)conn->response.headers.content_length);
        }

        // check "Connection" header
        else if (0 == strcmp(h_name, "Connection"))
        {
            conn->response.headers.connection = http_header_connection_parse(h_value);
            switch (conn->response.headers.connection)
            {
            case HTTP_CONNECTION_CLOSE:
                INFO("HttpConn_%p \"%s\" connection header - should be closed\n",
                     conn, h_value);
                break;

            case HTTP_CONNECTION_KEEP_ALIVE:
                INFO("HttpConn_%p \"%s\" connection header - should be kept alive\n",
                     conn, h_value);
                break;

            default:
                WARN("HttpConn_%p unknown connection \"%s\" header, ignored\n",
                     conn, h_value);
            }
        }

        // TODO: more headers: "Content-Type", "Server", "Transfer-Encoding" etc...
    }

    if (name) *name = h_name;
    if (value) *value= h_value;
    TRACE("HttpConn_%p leave http_conn_recv_response_header()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_ignore_response_headers() implementation.
 */
int http_conn_ignore_response_headers(struct HTTP_Conn *conn)
// see http_conn_ignore_request_headers() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_ignore_response_headers()\n", conn);

    // have to receive response headers?
    while (!http_conn_has_flag(conn, CONN_FLAG_RESPONSE_HEADERS_RECEIVED))
    {
        const char *h_name = 0;
        const char *h_value = 0;
        const int err = http_conn_recv_response_header(conn, &h_name, &h_value);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed

        if (h_name && h_value)
        {
            DEBUG("HttpConn_%p response header \"%s: %s\" ignored\n",
                  conn, h_name, h_value);
        }
    }

    TRACE("HttpConn_%p leave http_conn_ignore_response_headers()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_recv_response_body() implementation.
 */
int http_conn_recv_response_body(struct HTTP_Conn *conn,
                                 void *buf, int *len)
// see http_conn_recv_request_body() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_recv_response_body(%p, %d)\n", conn, buf, *len);

    // have to receive rest of response headers?
    if (!http_conn_has_flag(conn, CONN_FLAG_RESPONSE_HEADERS_RECEIVED))
    {
        DEBUG("HttpConn_%p ignoring all response headers...\n", conn);
        const int err = http_conn_ignore_response_headers(conn);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    // receive via helper
    const int err = http_conn_recv_body(conn, buf, len);
    if (HTTP_ERR_SUCCESS != err)
        return err;

    // update number of content bytes read
    if (*len > 0)
    {
        conn->internal.content_pos += *len;
        DEBUG("HttpConn_%p total %lld/%lld bytes read of response body\n",
              conn, (long long int)conn->internal.content_pos,
              (long long int)conn->response.headers.content_length);
    }

    TRACE("HttpConn_%p leave http_conn_recv_response_body(%d)\n", conn, *len);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_ignore_response_body() implementation.
 */
int http_conn_ignore_response_body(struct HTTP_Conn *conn)
// see http_conn_ignore_request_body() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_ignore_response_body()\n", conn);

    // have to receive rest of response headers?
    if (!http_conn_has_flag(conn, CONN_FLAG_RESPONSE_HEADERS_RECEIVED))
    {
        DEBUG("HttpConn_%p ignoring all response headers...\n", conn);
        const int err = http_conn_ignore_response_headers(conn);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    // ignore remaining body if "Content-Length" header is known
    if (conn->response.headers.content_length > 0)
    {
        int64_t rem = (conn->response.headers.content_length - conn->internal.content_pos);
        if (rem > 0)
        {
            uint8_t tmp_buf[HTTP_CONN_BUF_SIZE];
            INFO("HttpConn_%p ignoring %lld bytes of response body...\n",
                 conn, (long long int)rem);
            while (rem > 0)
            {
                int n = (rem <= (int64_t)sizeof(tmp_buf)) ? (int)rem : (int)sizeof(tmp_buf);
                const int err = http_conn_recv_response_body(conn, tmp_buf, &n);
                if (HTTP_ERR_SUCCESS != err)
                    return err; // failed
                if (!n) // no data read
                {
                    // TODO: wait a bit and try again?
                    ERROR("HttpConn_%p not ALL data received: %lld bytes remain\n",
                          conn, (long long int)rem);
                    return HTTP_ERR_READ; // failed
                }
                rem -= n;
            }
        }
    }
    else
    {
        uint8_t tmp_buf[HTTP_CONN_BUF_SIZE];
        INFO("HttpConn_%p ignoring ALL bytes of response body...\n", conn);

        while (1)
        {
            int n = sizeof(tmp_buf);
            const int err = http_conn_recv_response_body(conn, tmp_buf, &n);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
            if (!n) // no data read
            {
                // ERROR("HttpConn_%p not ALL data received\n", conn);
                // return HTTP_ERR_READ; // failed
                break; // done
            }
        }
    }

    TRACE("HttpConn_%p leave http_conn_ignore_response_body()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}

#endif // HTTP connection - client related

// HTTP connection - server related
#if defined(HTTP_SERVER)

/**
 * @brief Parse HTTP request line.
 * @param[in] conn Connection to parse request line of.
 * @param[in] line Begin of request line.
 *                 Should be NULL-terminated for logging purposes.
 * @param[in] len Length of request line in bytes.
 * @return Zero on success.
 */
static int http_conn_parse_request_line(struct HTTP_Conn *conn, uint8_t *line, int len)
{
    TRACE("HttpConn_%p enter http_conn_parse_request_line(\"%.*s\", %d)\n", conn, len, line, len);

    // parse HTTP method (in order of priority)
    enum HTTP_Method method = HTTP_UNKNOWN_METHOD;
    uint8_t *method_end = (uint8_t*)memchr(line, ' ', len);
    if (method_end)
    {
        const int method_len = method_end - line;
        *method_end = 0; // NULL-terminate the method
        if (method_len == 3 && 0 == memcmp(line, "GET", 3))
            method = HTTP_GET;
        else if (method_len == 3 && 0 == memcmp(line, "PUT", 3))
            method = HTTP_PUT;
        else if (method_len == 4 && 0 == memcmp(line, "POST", 4))
            method = HTTP_POST;
        else if (method_len == 6 && 0 == memcmp(line, "DELETE", 6))
            method = HTTP_DELETE;
        else if (method_len == 4 && 0 == memcmp(line, "HEAD", 4))
            method = HTTP_HEAD;
        else if (method_len == 7 && 0 == memcmp(line, "OPTIONS", 7))
            method = HTTP_OPTIONS;
        else if (method_len == 7 && 0 == memcmp(line, "CONNECT", 7))
            method = HTTP_CONNECT;
        else
        {
            WARN("HttpConn_%p unknown method \"%.*s\" found, ignored\n",
                 conn, method_len, line);
            // try to ignore unknown method...
        }

        line += method_len + 1; // skip space
        len -= method_len + 1;  // skip space
    }
    else
    {
        ERROR("HttpConn_%p bad REQUEST line: %s\n", conn, "no HTTP method found");
        return HTTP_ERR_BAD_REQUEST_NO_METHOD; // failed
    }

    // get URI
    uint8_t *uri_end = (uint8_t*)memchr(line, ' ', len);
    if (uri_end)
    {
        const int uri_len = uri_end - line;
        const int err = http_conn_set_request_uri(conn, (const char*)line, uri_len);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed

        line += uri_len + 1; // skip space
        len -= uri_len + 1;  // skip space
    }
    else
    {
        ERROR("HttpConn_%p bad REQEUST line: %s\n", conn, "no URI found");
        return HTTP_ERR_BAD_REQUEST_NO_URI; // failed
    }

    // parse HTTP protocol (in order of priority)
    enum HTTP_Proto proto = HTTP_UNKNOWN_PROTO;
    if (len >= 8 && 0 == memcmp(line, "HTTP/1.0", 8))
    {
        proto = HTTP_PROTO_1_0;
        line += 8;
        len -= 8;
    }
    else if (len >= 8 && 0 == memcmp(line, "HTTP/1.1", 8))
    {
        proto = HTTP_PROTO_1_1;
        line += 8;
        len -= 8;
    }
    else
    {
        WARN("HttpConn_%p unknown protocol \"%s\" found, ignored\n",
             conn, line);
        line += len;
        len -= len;
        // try to continue...
    }

    if (len != 0)
    {
        WARN("HttpConn_%p garbage at the end of REQUEST line: \"%s\", ignored\n",
             conn, line);
        // garbage is ignored
    }

    http_conn_set_request_method(conn, method);
    http_conn_set_request_proto(conn, proto);

    TRACE("HttpConn_%p leave http_conn_parse_request_line()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_recv_request_line() implementation.
 */
int http_conn_recv_request_line(struct HTTP_Conn *conn)
// see http_conn_recv_response_status() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_recv_request_line()\n", conn);
    struct HTTP_ConnInternal *ci = &conn->internal;

    // have to receive request line?
    if (http_conn_has_flag(conn, CONN_FLAG_REQUEST_LINE_RECEIVED))
    {
        TRACE("HttpConn_%p request line already received\n", conn);
        return HTTP_ERR_SUCCESS; // OK
    }

    while (1) // read request line
    {
        // do we have space in working buffer?
        if (HTTP_CONN_BUF_SIZE - ci->buf_len > 0)
        {
            // getting some data into working buffer
            const int err = http_conn_wbuf_grow(conn);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
        }
        else
        {
            ERROR("HttpConn_%p request line too big to fit working buffer\n", conn);
            return HTTP_ERR_FAILED; // failed
        }

        // check the whole line received
        uint8_t *line_beg = ci->buf + ci->buf_pos;
        const uint8_t *line_end = (const uint8_t*)http_find_crlf(line_beg,
                                               ci->buf_len - ci->buf_pos);
        if (!line_end)
            continue; // need more data

        const int line_len = line_end - line_beg;
        if (!line_len)
        {
            ERROR("HttpConn_%p empty request line received\n", conn);
            http_conn_set_flag(conn, CONN_FLAG_REQUEST_HEADERS_RECEIVED);
            return HTTP_ERR_FAILED; // failed
        }

        // parse request line
        line_beg[line_len] = 0; // NULL-terminate for logging purposes
        const int err = http_conn_parse_request_line(conn, line_beg, line_len);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed

        ci->buf_pos += line_len + 2; // + "\r\n"
        break; // done
    }

    // mark request line as received
    http_conn_set_flag(conn, CONN_FLAG_REQUEST_LINE_RECEIVED);
    INFO("HttpConn_%p request line \"%s %s %s\" received\n",
         conn, http_conn_get_request_method(conn),
         http_conn_get_request_uri(conn),
         http_conn_get_request_proto(conn));

    TRACE("HttpConn_%p leave http_conn_recv_request_line()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_recv_request_header() implementation.
 */
int http_conn_recv_request_header(struct HTTP_Conn *conn,
                                  const char **name,
                                  const char **value)
// see http_conn_recv_response_header() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_recv_request_header()\n", conn);

    // can we receive more headers?
    if (http_conn_has_flag(conn, CONN_FLAG_REQUEST_HEADERS_RECEIVED))
    {
        ERROR("HttpConn_%p all headers already received\n", conn);
        return HTTP_ERR_ILLEGAL;
    }

    // have we receive request line?
    if (!http_conn_has_flag(conn, CONN_FLAG_REQUEST_LINE_RECEIVED))
    {
        DEBUG("HttpConn_%p try to receive request line...\n", conn);
        const int err = http_conn_recv_request_line(conn);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    const char *h_name = 0;
    const char *h_value = 0;
    const int err = http_conn_recv_header(conn, &h_name, &h_value);
    if (HTTP_ERR_SUCCESS != err)
        return err; // failed
    if (h_name && h_value)
    {
        INFO("HttpConn_%p request header \"%s: %s\" received\n",
             conn, h_name, h_value);
    }
    else
    {
        INFO("HttpConn_%p EMPTY line received - end of request headers\n", conn);
        http_conn_set_flag(conn, CONN_FLAG_REQUEST_HEADERS_RECEIVED); // can receive body now
    }

    // handle common headers
    if (h_name && h_value)
    {
        // check "Content-Length" header
        if (0 == strcmp(h_name, "Content-Length"))
        {
            conn->request.headers.content_length = strtoll(h_value, 0, 10);
            // TODO: check extra data and the end of value?
            INFO("HttpConn_%p request content length parsed as %lld\n",
                 conn, (long long int)conn->request.headers.content_length);
        }

        // check "Connection" header
        else if (0 == strcmp(h_name, "Connection"))
        {
            conn->request.headers.connection = http_header_connection_parse(h_value);
            switch (conn->response.headers.connection)
            {
            case HTTP_CONNECTION_CLOSE:
                INFO("HttpConn_%p \"%s\" connection header - should be closed\n",
                     conn, h_value);
                break;

            case HTTP_CONNECTION_KEEP_ALIVE:
                INFO("HttpConn_%p \"%s\" connection header - should be kept alive\n",
                     conn, h_value);
                break;

            default:
                WARN("HttpConn_%p unknown connection \"%s\" header, ignored\n",
                     conn, h_value);
            }
        }

        // TODO: more headers: "Content-Type", "Server", "Transfer-Encoding" etc...
    }

    if (name) *name = h_name;
    if (value) *value= h_value;
    TRACE("HttpConn_%p leave http_conn_recv_request_header()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_ignore_request_headers() implementation.
 */
int http_conn_ignore_request_headers(struct HTTP_Conn *conn)
// see http_conn_ignore_response_headers() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_ignore_request_headers()\n", conn);

    // have to receive request headers?
    while (!http_conn_has_flag(conn, CONN_FLAG_REQUEST_HEADERS_RECEIVED))
    {
        const char *h_name = 0;
        const char *h_value = 0;
        const int err = http_conn_recv_request_header(conn, &h_name, &h_value);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed

        if (h_name && h_value)
        {
            DEBUG("HttpConn_%p request header \"%s: %s\" ignored\n",
                  conn, h_name, h_value);
        }
    }

    TRACE("HttpConn_%p leave http_conn_ignore_request_headers()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_recv_request_body() implementation.
 */
int http_conn_recv_request_body(struct HTTP_Conn *conn,
                                void *buf, int *len)
// see http_conn_recv_response_body() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_recv_request_body(%p, %d)\n", conn, buf, *len);

    // have to receive rest of response headers?
    if (!http_conn_has_flag(conn, CONN_FLAG_REQUEST_HEADERS_RECEIVED))
    {
        DEBUG("HttpConn_%p ignoring all request headers...\n", conn);
        const int err = http_conn_ignore_request_headers(conn);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    // receive via helper
    const int err = http_conn_recv_body(conn, buf, len);
    if (HTTP_ERR_SUCCESS != err)
        return err;

    // update number of content bytes read
    if (*len > 0)
    {
        conn->internal.content_pos += *len;
        DEBUG("HttpConn_%p total %lld/%lld bytes read of request body\n",
              conn, (long long int)conn->internal.content_pos,
              (long long int)conn->request.headers.content_length);
    }

    TRACE("HttpConn_%p leave http_conn_recv_request_body(%d)\n", conn, *len);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_ignore_request_body() implementation.
 */
int http_conn_ignore_request_body(struct HTTP_Conn *conn)
// see http_conn_ignore_response_body() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_ignore_request_body()\n", conn);

    // have to receive rest of request headers?
    if (!http_conn_has_flag(conn, CONN_FLAG_REQUEST_HEADERS_RECEIVED))
    {
        DEBUG("HttpConn_%p ignoring all request headers...\n", conn);
        const int err = http_conn_ignore_request_headers(conn);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    // ignore remaining body if "Content-Length" header is known
    if (conn->request.headers.content_length > 0)
    {
        int64_t rem = (conn->request.headers.content_length - conn->internal.content_pos);
        if (rem > 0)
        {
            uint8_t tmp_buf[HTTP_CONN_BUF_SIZE];
            INFO("HttpConn_%p ignoring %lld bytes of request body...\n",
                 conn, (long long int)rem);
            while (rem > 0)
            {
                int n = (rem <= (int64_t)sizeof(tmp_buf)) ? (int)rem : (int)sizeof(tmp_buf);
                const int err = http_conn_recv_request_body(conn, tmp_buf, &n);
                if (HTTP_ERR_SUCCESS != err)
                    return err; // failed
                if (!n) // no data read
                {
                    // TODO: wait a bit and try again?
                    ERROR("HttpConn_%p not ALL data received: %lld bytes remain\n",
                          conn, (long long int)rem);
                    return HTTP_ERR_READ; // failed
                }
                rem -= n;
            }
        }
    }
    else
    {
        // we don't know how much to ignore
    }

    TRACE("HttpConn_%p leave http_conn_ignore_request_body()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_send_response_status() implementation.
 */
int http_conn_send_response_status(struct HTTP_Conn *conn)
// see http_conn_send_request_line() for the almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_send_response_status()\n", conn);
    struct HTTP_ConnInternal *ci = &conn->internal;

    // can we send response status?
    if (http_conn_has_flag(conn, CONN_FLAG_RESPONSE_STATUS_SENT))
    {
        ERROR("HttpConn_%p response status already sent\n", conn);
        return HTTP_ERR_ILLEGAL; // failed
    }

    // have to receive request headers & body?
    if (1) // !http_conn_has_flag(conn, CONN_FLAG_REQUEST_HEADERS_RECEIVED))
    {
        DEBUG("HttpConn_%p ensure full request received...\n", conn);
        const int err = http_conn_ignore_request_body(conn);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    // request received, reset the working buffer
    ci->buf_pos = 0;
    ci->buf_len = 0;
    DEBUG("HttpConn_%p reset working buffer{pos:%d, len:%d}\n",
          conn, ci->buf_pos, ci->buf_len);

    // reason phrase with default fallback
    const char *reason = http_conn_get_response_reason(conn);
    if (!reason || !reason[0]) // empty?
    {
        // if status is still unknown, use any non-empty string
        WARN("HttpConn_%p reason phrase for status %d is unknow\n",
             conn, http_conn_get_response_status(conn));
        reason = "Unknown";
    }

    while (1) // at most two iterations
    {
        // try to put PROTOCOL STATUS REASON to the end of internal buffer
        const int space = HTTP_CONN_BUF_SIZE - ci->buf_len;
        const int err = snprintf((char*)&ci->buf[ci->buf_len], space,
                                 "%s %d %s\r\n",
                                 http_conn_get_response_proto(conn),
                                 http_conn_get_response_status(conn),
                                 reason);
        if (err < 0)
        {
            ERROR("HttpConn_%p failed to format response status line: (%d) %s\n",
                  conn, errno, strerror(errno));
            return HTTP_ERR_FAILED; // failed
        }
        else if (err >= space)
        {
            // in some rare cases the response status line
            // could be too big to fit working buffer
            if (space == HTTP_CONN_BUF_SIZE)
            {
                ERROR("HttpConn_%p failed to send response status line: %s\n",
                      conn, "too long to fit internal buffer");
                return HTTP_ERR_FAILED; // failed
            }

            // buffer is overflow!
            DEBUG("HttpConn_%p sending working buffer of %d bytes...\n", conn, ci->buf_len);
            const int err = http_conn_send_all(conn, ci->buf, ci->buf_len);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
            ci->buf_len = 0; // buffer is empty now
            continue; // try again with empty buffer...
        }

        ci->buf_len += err;
        break; // done
    }

    http_conn_set_flag(conn, CONN_FLAG_RESPONSE_STATUS_SENT);
    INFO("HttpConn_%p response status line \"%s %d %s\" buffered\n", conn,
         http_conn_get_response_proto(conn),
         http_conn_get_response_status(conn), reason);
    DEBUG("HttpConn_%p internal buffer{pos:%d, len:%d}\n",
          conn, ci->buf_pos, ci->buf_len);

    TRACE("HttpConn_%p leave http_conn_send_response_status()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_send_response_header() implementation.
 */
int http_conn_send_response_header(struct HTTP_Conn *conn,
                                   const char *name,
                                   const char *value)
// see http_conn_send_request_header() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_send_response_header(\"%s\", \"%s\")\n", conn, name, value);
    struct HTTP_ConnInternal *ci = &conn->internal;

    // can we send header?
    if (http_conn_has_flag(conn, CONN_FLAG_RESPONSE_HEADERS_SENT))
    {
        ERROR("HttpConn_%p all response headers already sent\n", conn);
        return HTTP_ERR_ILLEGAL; // failed
    }

    // have to send response status line first
    if (!http_conn_has_flag(conn, CONN_FLAG_RESPONSE_STATUS_SENT))
    {
        // send response status line PROTOCOL STATUS REASON
        DEBUG("HttpConn_%p sending response status line...\n", conn);
        const int err = http_conn_send_response_status(conn);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    // send header via helper
    const int err = http_conn_send_header(conn, name, value);
    if (HTTP_ERR_SUCCESS != err)
        return err;

    INFO("HttpConn_%p response header \"%s: %s\" buffered\n", conn, name, value);
    DEBUG("HttpConn_%p internal buffer{pos:%d, len:%d}\n",
          conn, ci->buf_pos, ci->buf_len);

    TRACE("HttpConn_%p leave http_conn_send_response_header()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_send_response_body() implementation.
 */
int http_conn_send_response_body(struct HTTP_Conn *conn,
                                 const void *buf, int len)
// see http_conn_send_request_body() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_send_response_body(%p, %d)\n", conn, buf, len);

    // can we send body?
    if (http_conn_has_flag(conn, CONN_FLAG_RESPONSE_BODY_SENT))
    {
        ERROR("HttpConn_%p response body already sent\n", conn);
        return HTTP_ERR_ILLEGAL; // failed
    }

    // have to finish all headers
    if (!http_conn_has_flag(conn, CONN_FLAG_RESPONSE_HEADERS_SENT))
    {
        if (!http_conn_has_flag(conn, CONN_FLAG_RESPONSE_STATUS_SENT))
        {
            // send response status line "PROTOCOL STATUS REASON"
            DEBUG("HttpConn_%p sending response status line...\n", conn);
            const int err = http_conn_send_response_status(conn);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
        }

        // write empty line - "headers end" marker
        DEBUG("HttpConn_%p sending EMPTY line...\n", conn);
        const int err = http_conn_send(conn, "\r\n", 2);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed

        http_conn_set_flag(conn, CONN_FLAG_RESPONSE_HEADERS_SENT); // headers sent
        INFO("HttpConn_%p ALL response headers buffered\n", conn);
    }

    if (len > 0)
    {
        // write data to buffer
        DEBUG("HttpConn_%p sending %d bytes of data...\n", conn, len);
        const int err = http_conn_send(conn, buf, len);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
    }

    TRACE("HttpConn_%p leave http_conn_send_response_body()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_conn_flush_response() implementation.
 */
int http_conn_flush_response(struct HTTP_Conn *conn)
// see http_conn_flush_request() for almost the same implementation
{
    TRACE("HttpConn_%p enter http_conn_flush_response()\n", conn);
    struct HTTP_ConnInternal *ci = &conn->internal;

    // have to flush?
    if (http_conn_has_flag(conn, CONN_FLAG_RESPONSE_BODY_SENT))
    {
        TRACE("HttpConn_%p response already finished\n", conn);
        return HTTP_ERR_SUCCESS; // still OK
    }

    // write empty body part (will write request line and all headers)
    const int err = http_conn_send_response_body(conn, "", 0);
    if (HTTP_ERR_SUCCESS != err)
        return err; // failed

    // flush buffer
    if (ci->buf_len > 0)
    {
        DEBUG("HttpConn_%p sending working buffer of %d bytes...\n", conn, ci->buf_len);
        const int err = http_conn_send_all(conn, ci->buf, ci->buf_len);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
        ci->buf_len = 0; // buffer is empty now
    }

    http_conn_set_flag(conn, CONN_FLAG_RESPONSE_BODY_SENT); // body sent
    INFO("HttpConn_%p FULL response sent\n", conn);

    TRACE("HttpConn_%p leave http_conn_flush_response()\n", conn);
    return HTTP_ERR_SUCCESS; // OK
}

#endif // HTTP connection - server related

#endif // HTTP connection


// HTTP client
#if defined(HTTP_CLIENT)

/*
 * http_client_new() implementation.
 */
int http_client_new(enum SSL_Proto proto, struct HTTP_Client **client_)
{
    TRACE("enter http_client_new(%s)\n", ssl_proto_string(proto));

    // select appropriate SSL protocol version
    WOLFSSL_METHOD *method = 0;
    switch (proto)
    {
    #ifdef WOLFSSL_ALLOW_SSLV3
        case SSL_PROTO_SSLv3:
            method = wolfSSLv3_client_method();
            break;
    #endif // WOLFSSL_ALLOW_SSLV3

    #ifdef WOLFSSL_ALLOW_TLSV10
        case SSL_PROTO_TLSv1_0:
            method = wolfTLSv1_client_method();
            break;
    #endif // WOLFSSL_ALLOW_TLSV10

        case SSL_PROTO_TLSv1_1:
            method = wolfTLSv1_1_client_method();
            break;

        case SSL_PROTO_TLSv1_2:
            method = wolfTLSv1_2_client_method();
            break;

    #ifdef WOLFSSL_TLS13
        case SSL_PROTO_TLSv1_3:
            method = wolfTLSv1_3_client_method();
            break;
    #endif // WOLFSSL_TLS13

        case SSL_PROTO_TLSv1_2_TO_SSLv3: // use highest possible version from SSLv3 to TLS 1.2
            method = wolfSSLv23_client_method();
            break;

        default:
            ERROR("\"%s\" is unknown or unsupported SSL protocol\n",
                  ssl_proto_string(proto));
            return HTTP_ERR_ILLEGAL; // failed
    }

    // allocate memory
    struct HTTP_Client *client = (struct HTTP_Client*)malloc(sizeof(*client));
    if (!client)
    {
        ERROR("http_client_new(): FAILED to allocate %d bytes of memory: (%d) %s\n",
              (int)sizeof(*client), errno, strerror(errno));
        return HTTP_ERR_NO_MEMORY; // failed
    }
    DEBUG("HttpClient_%p memory block of %d bytes allocated\n",
          client, (int)sizeof(*client));

    // default values
    client->ctx = 0;

    // create SSL context
    client->ctx = wolfSSL_CTX_new(method);
    if (!client->ctx)
    {
        ERROR("HttpClient_%p FAILED to create SSL context\n", client);
        http_client_free(client);
        return HTTP_ERR_FAILED; // failed
    }
    DEBUG("HttpClient_%p SSL context SSL_CTX_%p created\n", client, client->ctx);

#if HTTP_CLIENT_CONN_CACHE_SIZE > 0
    // reset the whole connection cache
    memset(client->conn_cache, 0, sizeof(client->conn_cache));
    DEBUG("HttpClient_%p reset connection cache of %d items\n",
          client, HTTP_CLIENT_CONN_CACHE_SIZE);
#endif // HTTP_CLIENT_CONN_CACHE_SIZE

#if HTTP_RESOLVE_CACHE_SIZE > 0
    // reset the whole resolve cache
    memset(client->resolve_cache, 0, sizeof(client->resolve_cache));
    DEBUG("HttpClient_%p reset resolve cache of %d items\n",
          client, HTTP_RESOLVE_CACHE_SIZE);
#endif // HTTP_RESOLVE_CACHE_SIZE

    *client_ = client;
    TRACE("HttpClient_%p leave http_client_new()\n", client);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_client_free() implementation.
 */
void http_client_free(struct HTTP_Client *client)
{
    TRACE("HttpClient_%p enter http_client_free()\n", client);

    if (!client)
    {
        TRACE("nothing to release\n");
        return; // nothing to release
    }

#if HTTP_CLIENT_CONN_CACHE_SIZE > 0
    // release all cached connections
    for (int i = 0; i < HTTP_CLIENT_CONN_CACHE_SIZE; ++i)
    {
        struct HTTP_ClientConnCacheItem *item = &client->conn_cache[i];
        if (!item->conn)
            continue;

        DEBUG("HttpClient_%p releasing cached HttpConn_%p...\n", client, item->conn);
        http_conn_free(item->conn);
        memset(item, 0, sizeof(*item));
    }
#endif // HTTP_CLIENT_CONN_CACHE_SIZE

#if HTTP_RESOLVE_CACHE_SIZE > 0
    // there is nothing to release in resolve cache
#endif // HTTP_RESOLVE_CACHE_SIZE

    // release SSL context
    if (client->ctx)
    {
        DEBUG("HttpClient_%p releasing SSL_CTX_%p\n",
              client, client->ctx);
        wolfSSL_CTX_free(client->ctx);
        client->ctx = 0;
    }

    // release client
    DEBUG("HttpClient_%p releasing...\n", client);
    free(client);

    TRACE("HttpClient_%p leave http_client_free()\n", client);
}

// connection cache
#if HTTP_CLIENT_CONN_CACHE_SIZE > 0

/**
 * @brief Find and take connection from cache.
 * @param[in] client HTTP client.
 * @param[in] ipv4 Target IPv4 address.
 * @param[in] port Target port number.
 * @return Found connection or `NULL`.
 */
static struct HTTP_Conn* http_client_conn_cache_take(struct HTTP_Client *client,
                                                     uint32_t ipv4, int port)
{
    // TODO: lock mutex

    // iterate over all cached items
    for (int i = 0; i < HTTP_CLIENT_CONN_CACHE_SIZE; ++i)
    {
        struct HTTP_ClientConnCacheItem *item = &client->conn_cache[i];
        struct HTTP_Conn *conn = item->conn;
        if (!conn)
            continue;

        if (conn->remote_ipv4 != ipv4)
            continue; // IP address mismatch
        if (conn->remote_port != port)
            continue; // port number mismatch

        // matched, take it from cache!
        memset(item, 0, sizeof(*item));
        return conn;
    }

    return 0; // not found
}


/**
 * @brief Put connection to cache.
 *
 * If there is no available space in connection cache then
 * connection is released.
 *
 * @param[in] client HTTP client.
 * @param[in] conn Connection to cache.
 * @return Zero on success.
 */
static void http_client_conn_cache_save(struct HTTP_Client *client,
                                        struct HTTP_Conn *conn)
{
    struct HTTP_ClientConnCacheItem *place = 0;

    // TODO: lock mutex

    // iterate over all cached items
    for (int i = 0; i < HTTP_CLIENT_CONN_CACHE_SIZE; ++i)
    {
        struct HTTP_ClientConnCacheItem *item = &client->conn_cache[i];
        struct HTTP_Conn *conn = item->conn;
        if (!conn)
        {
            place = item;
            break; // done
        }

        // TODO: check the connection is still alive!
    }

    if (!place)
    {
        // TODO: no place found, remove oldest/useless connection?
    }

    if (place)
    {
        // save connection!
        place->conn = conn;
    }
    else
    {
        // still no place found
        // just release connection
        http_conn_free(conn);
    }
}

#endif // connection cache


// resolve cache
#if HTTP_RESOLVE_CACHE_SIZE > 0

/**
 * @brief Calculate digest on host name.
 * @param[in] host Target host name.
 * @param[in] host_len Target host name length in bytes.
 * @param[in] digest Buffer to save digest.
 * @param[in] digest_len Buffer length in bytes.
 * @return Zero on success.
 */
static int http_client_host_digest(const char *host, int host_len,
                                   void *digest, int digest_len)
{
    // calculate digest
    const int err = wc_Hash(WC_HASH_TYPE_SHA,
            (const byte*)host, host_len,
            (byte*)digest, digest_len);
    if (err != 0)
    {
        ERROR("failed to calculate SHA-1 hash: %d\n", err);
        return HTTP_ERR_FAILED;
    }

    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Find existing resolve cache item for target host.
 * @param[in] client HTTP client.
 * @param[in] host_digest Target host digest.
 * @return Cache item or `NULL` if nothing found.
 */
static struct HTTP_ResolveCacheItem* http_client_resolve_cache_find(struct HTTP_Client *client,
                                                                    const void *host_digest)
{
    // iterate over all items
    for (int i = 0; i < HTTP_RESOLVE_CACHE_SIZE; ++i)
    {
        struct HTTP_ResolveCacheItem *item = &client->resolve_cache[i];
        if (!item->ipv4)
            continue; // no address, check next

        if (0 == memcmp(item->host_dig, host_digest, sizeof(item->host_dig)))
            return item;
    }

    return 0; // not found
}


/**
 * @brief Find oldest/useless resolve cache item.
 *
 * This item will be replaced with new the host information.
 *
 * @param[in] client HTTP client.
 * @return Cache item.
 */
static struct HTTP_ResolveCacheItem* http_client_resolve_cache_find_place(struct HTTP_Client *client)
{
    struct HTTP_ResolveCacheItem *place = 0;

    // iterate over all items
    for (int i = 0; i < HTTP_RESOLVE_CACHE_SIZE; ++i)
    {
        struct HTTP_ResolveCacheItem *item = &client->resolve_cache[i];
        if (!item->ipv4) // item is empty
            return item; // use it

        // find the less useful item
        if (!place || item->use_count < place->use_count)
            place = item;
    }

    return place;
}


/**
 * @brief Remove resolve cache for specific IP address.
 * @param client HTTP client.
 * @param ipv4 IP address to remove.
 * @return Number of cache entries removed.
 */
static int http_client_resolve_cache_remove(struct HTTP_Client *client, uint32_t ipv4)
{
    int n = 0;

    // iterate over all items
    for (int i = 0; i < HTTP_RESOLVE_CACHE_SIZE; ++i)
    {
        struct HTTP_ResolveCacheItem *item = &client->resolve_cache[i];
        if (item->ipv4 == ipv4)
        {
            item->ipv4 = 0; // clear it
            n += 1;
        }
    }

    return n;
}

#endif // resolve cache


/*
 * http_client_load_verify_cert_file() implementation.
 */
int http_client_load_verify_cert_file(struct HTTP_Client *client,
                                      const char *cert_file)
{
    TRACE("HttpClient_%p enter http_client_load_verify_cert_file(\"%s\")\n", client, cert_file);

#if defined(NO_FILESYSTEM)
    ERROR("HttpClient_%p no filesystem available to load certificate\n", client);
    return HTTP_ERR_ILLEGAL; // failed
#else

    if (cert_file)
    {
        // load trusted certificate into SSL context
        const int err = wolfSSL_CTX_load_verify_locations(client->ctx, cert_file, NULL);
        if (WOLFSSL_SUCCESS != err)
        {
            ERROR("HttpClient_%p FAILED to load \"%s\" certificate: %s\n",
                  client, cert_file, "please check file location or format");
            return HTTP_ERR_BAD_CERT; // failed
        }
        INFO("HttpClient_%p use trusted certificate from \"%s\"\n", client, cert_file);
    }

    TRACE("HttpClient_%p leave http_client_load_verify_cert_file()\n", client);
    return HTTP_ERR_SUCCESS; // OK
#endif // !NO_FILESYSTEM
}


/*
 * http_client_load_verify_cert_asn1() implementation.
 */
int http_client_load_verify_cert_asn1(struct HTTP_Client *client,
                                      const void *cert, int cert_len)
{
    TRACE("HttpClient_%p enter http_client_load_verify_cert_asn1(%p, %d)\n", client, cert, cert_len);

    if (cert && cert_len)
    {
        // load trusted certificate into SSL context
        const int err = wolfSSL_CTX_load_verify_buffer(client->ctx,
                                                       (const unsigned char *)cert,
                                                       (long)cert_len,
                                                       WOLFSSL_FILETYPE_ASN1);
        if (WOLFSSL_SUCCESS != err)
        {
            ERROR("HttpClient_%p FAILED to load certificate\n", client);
            return HTTP_ERR_BAD_CERT; // failed
        }
        INFO("HttpClient_%p use certificate from %d bytes buffer at %p\n",
             client, cert_len, cert);
    }

    TRACE("HttpClient_%p leave http_client_load_verify_cert_asn1()\n", client);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_client_set_cipher_list() implementation.
 */
int http_client_set_cipher_list(struct HTTP_Client *client,
                                const char *cipher_list)
{
    TRACE("HttpClient_%p enter http_client_set_cipher_list(\"%s\")\n", client, cipher_list);

    // set cipher list
    const int err = wolfSSL_CTX_set_cipher_list(client->ctx, cipher_list);
    if (WOLFSSL_SUCCESS != err)
    {
        ERROR("HttpClient_%p FAILED to set \"%s\" as cipher list\n",
              client, cipher_list);
        return HTTP_ERR_BAD_CIPHER_LIST; // failed
    }
    INFO("HttpClient_%p use the following ciphers: \"%s\"\n", client, cipher_list);

    TRACE("HttpClient_%p leave http_client_set_cipher_list()\n", client);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Connect to a host.
 *
 * This is helper function.
 *
 * @param[in] client HTTP client.
 * @param[out] pconn New or cached connection.
 * @param[in] secure If non-zero then secure connection should be used.
 * @param[in] flags Connection flags.
 * @param[in] host Host name.
 * @param[in] host_len Host name length in bytes.
 *                     `-1` if NULL-terminated.
 * @param[in] port Port number to connect.
 * @return Zero on success.
 */
static int http_client_connect(struct HTTP_Client *client,
                               struct HTTP_Conn **pconn, int secure, uint32_t flags,
                               const char *host, int host_len, int port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;          // IPv4
    addr.sin_addr.s_addr = INADDR_ANY;  // any for now
    addr.sin_port = port_h2n(port);
    (void)flags; // fake usage

    if (1) // resolve host name
    {
#if HTTP_RESOLVE_CACHE_SIZE > 0
        uint8_t host_digest[HTTP_HOST_DIGEST_SIZE]; // TODO: check how fast is the digest calculation
        const int err = http_client_host_digest(host, host_len, &host_digest, sizeof(host_digest));
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
        struct HTTP_ResolveCacheItem *rc_item = http_client_resolve_cache_find(client, host_digest);
        if (rc_item) // TODO: check item lifetime
        {
            addr.sin_addr.s_addr = rc_item->ipv4;
            rc_item->use_count += 1; // update use count
            INFO("HttpClient_%p resolved as \"%d.%d.%d.%d\" from cache\n",
                 client, PRINT_IPV4_ADDR(addr));
        }
        else // no cached item, resolving...
        {
#endif // HTTP_RESOLVE_CACHE_SIZE

        // resolver requires NULL-terminated string as input,
        // so we have to copy our host to temporary buffer!
        char host_tmp[256];
        if (host_len >= (int)sizeof(host_tmp))
        {
            ERROR("HttpClient_%p host length is too big\n", client);
            // TODO: use dynamic memory buffer
            return HTTP_ERR_FAILED;
        }
        memcpy(host_tmp, host, host_len);
        host_tmp[host_len] = 0;

        // resolve IP address
        DEBUG("HttpClient_%p resolving the \"%s\" host...\n", client, host_tmp);
        struct hostent *entry = gethostbyname(host_tmp);
        if (entry)
        {
            // check address type
            if (AF_INET != entry->h_addrtype)
            {
                ERROR("HttpClient_%p failed to resolve \"%s\" host: %s\n", client,
                      host_tmp, "unknown address type");
                return HTTP_ERR_RESOLVE; // failed
            }

            //check address size
            if (sizeof(addr.sin_addr) != entry->h_length)
            {
                ERROR("HttpClient_%p failed to resolve \"%s\" host: %s\n", client,
                      host_tmp, "unknown address size");
                return HTTP_ERR_RESOLVE; // failed
            }

            // use the first available address
            const void *host_addr = entry->h_addr_list[0];
            memcpy(&addr.sin_addr, host_addr, sizeof(addr.sin_addr));

            INFO("HttpClient_%p host \"%s\" resolved as \"%d.%d.%d.%d\"\n",
                 client, host_tmp, PRINT_IPV4_ADDR(addr));
        }
        else
        {
           ERROR("HttpClient_%p failed to resolve \"%s\" host: %s\n",
                 client, host_tmp, "no entry found");
           return HTTP_ERR_RESOLVE; // failed
        }
#if HTTP_RESOLVE_CACHE_SIZE > 0
        rc_item = http_client_resolve_cache_find_place(client);
        if (rc_item)
        {
            DEBUG("HttpClient_%p put host \"%s\" to cache as \"%d.%d.%d.%d\"\n",
                  client, host_tmp, PRINT_IPV4_ADDR(addr));

            memcpy(rc_item->host_dig, host_digest, HTTP_HOST_DIGEST_SIZE);
            rc_item->ipv4 = addr.sin_addr.s_addr;
            rc_item->use_count = 0; // reset use count
        }
        } // no cache item
#endif // HTTP_RESOLVE_CACHE_SIZE
    } // resolve host name

    struct HTTP_Conn *conn;
#if HTTP_CLIENT_CONN_CACHE_SIZE > 0
    // first, try to use available cached connection
    conn = http_client_conn_cache_take(client,
                                       addr.sin_addr.s_addr,
                                       port_n2h(addr.sin_port));
    if (conn)
    {
        INFO("HttpClient_%p use cached connection HttpConn_%p\n",
             client, conn);
        http_conn_reset(conn);
    }
    else
    {
#endif // HTTP_CLIENT_CONN_CACHE_SIZE

    DEBUG("HttpClient_%p creating client socket...\n", client);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        ERROR("HttpClient_%p FAILED to create socket: (%d) %s\n",
              client, errno, strerror(errno));
        return HTTP_ERR_SOCKET; // failed
    }

    // connect to server
    DEBUG("HttpClient_%p connecting to \"%d.%d.%d.%d:%d\"...\n",
          client, PRINT_IPV4_ADDR_AND_PORT(addr));
    if (!!connect(fd, (const struct sockaddr*)&addr, sizeof(addr)))
    {
        ERROR("HttpClient_%p FAILED to connect: (%d) %s\n",
              client, errno, strerror(errno));

#if HTTP_RESOLVE_CACHE_SIZE > 0
        // if connect() failed then there is no sense to
        // cache that IP address, so just remove it...
        const int n_removed = http_client_resolve_cache_remove(client, addr.sin_addr.s_addr);
        INFO("HttpClient_%p %d entries with \"%d.%d.%d.%d\" address removed from cache\n",
              client, n_removed, PRINT_IPV4_ADDR(addr));
#endif // HTTP_RESOLVE_CACHE_SIZE

        return HTTP_ERR_CONNECT; // failed
    }

    // create new connection
    const int err = http_conn_new(secure ? client->ctx : 0, fd, &conn);
    if (HTTP_ERR_SUCCESS != err)
    {
        ERROR("HttpClient_%p failed to create connection\n", client);
        return err; // failed
    }

    // save remote endpoint address/port
    conn->remote_ipv4 = addr.sin_addr.s_addr;
    conn->remote_port = port_n2h(addr.sin_port);

    // SSL handshake
    if (conn->ssl)
    {
        // if (flags & HTTP_CONN_DOMAIN_NAME_CHECK) wolfSSL_check_domain_name(conn->ssl, http_conn_get_request_host(conn));

        DEBUG("HttpConn_%p SSL handshaking...\n", conn);
        const int err = wolfSSL_connect(conn->ssl);
        if (WOLFSSL_SUCCESS != err)
        {
            const int ssl_err = wolfSSL_get_error(conn->ssl, err);
            ERROR("HttpConn_%p FAILED to do SSL handshake: (%d) %s\n",
                  conn, ssl_err, wolfSSL_ERR_reason_error_string(ssl_err));
            http_conn_free(conn);
            return HTTP_ERR_HANDSHAKE; // failed
        }

        INFO("HttpConn_%p SSL handshake finished: %s\n", conn,
             wolfSSL_get_version(conn->ssl));
    }

#if HTTP_CLIENT_CONN_CACHE_SIZE > 0
    }
#endif // HTTP_CLIENT_CONN_CACHE_SIZE

    *pconn = conn;
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_client_do() implementation.
 */
int http_client_do(struct HTTP_Client *client,
                   enum HTTP_Method method,
                   const char *url,
                   HTTP_ClientCallback callback,
                   void *user_data,
                   uint32_t flags)
{
    const char *proto = 0;
    int         proto_len = 0;
    const char *host = 0;
    int         host_len = 0;
    int         port = 0; // invalid
    const char *uri = 0;
    int         uri_len = 0;

    struct HTTP_Conn *conn = 0;
    int secure = 0; // http/https
    int err;        // last error

    // parse URL
    err = http_parse_url(url, &proto, &proto_len,
                         &host, &host_len, &port,
                         &uri, &uri_len);
    if (HTTP_ERR_SUCCESS != err)
        goto done;

    // check port number
    if (port == 0)
    {
        ERROR("HttpClient_%p bad URL:\"%s\": %s\n", client,
              url, "no valid port number found");
        err = HTTP_ERR_BAD_URL_NO_PORT;
        goto done; // failed
    }

    // check host
    if (host_len == 0)
    {
        ERROR("HttpClient_%p bad URL:\"%s\": %s\n", client,
              url, "no valid host found");
        err = HTTP_ERR_BAD_URL_NO_HOST;
        goto done; // failed
    }

    // check URI
    if (uri_len == 0)
    {
        ERROR("HttpClient_%p bad URL:\"%s\": %s\n", client,
              url, "no valid URI found");
        err = HTTP_ERR_BAD_URL_NO_URI;
        goto done; // failed
    }

    // check protocol
    if (proto_len == 5 && 0 == memcmp(proto, "https", 5))
        secure = 1;
    else if (proto_len == 4 && 0 == memcmp(proto, "http", 4))
        secure = 0;
    else if (proto_len == 3 && 0 == memcmp(proto, "wss", 3))
        secure = 1;
    else if (proto_len == 2 && 0 == memcmp(proto, "ws", 2))
        secure = 0;
    else
    {
        ERROR("HttpClient_%p bad URL:\"%s\": %s\n", client,
              url, "unknown protocol found");
        err = HTTP_ERR_BAD_URL_PROTOCOL;
        goto done; // failed
    }

    const uint32_t t_start = misc_time_ms();
    (void)t_start; // fake use

    // connecting
    err = http_client_connect(client, &conn, secure, flags,
                              host, host_len, port);
    if (HTTP_ERR_SUCCESS != err)
        goto done; // failed

    DEBUG("HttpConn_%p connected in %d ms\n",
          conn, misc_time_ms() - t_start);

    // prepare request
    http_conn_set_request_method(conn, method);
    http_conn_set_request_proto(conn, HTTP_PROTO_1_1);
    err = http_conn_set_request_host(conn, host, host_len);
    if (HTTP_ERR_SUCCESS != err)
        goto done; // failed
    err = http_conn_set_request_uri(conn, uri, uri_len);
    if (HTTP_ERR_SUCCESS != err)
        goto done; // failed

done:

    DEBUG("HttpClient_%p calling callback(%d, HttpConn_%p, %p)...\n",
          client, err, conn, user_data);
    err = callback(err, conn, user_data);
    DEBUG("HttpClient_%p callback(%d) done\n", client, err);

    if (conn)
    {
        INFO("HttpClient_%p request \"%s %s/%s\" done with \"%d %s\" status in %d ms\n",
             client, http_conn_get_request_method(conn),
             http_conn_get_request_host(conn), http_conn_get_request_uri(conn),
             http_conn_get_response_status(conn), http_conn_get_response_reason(conn),
             misc_time_ms() - t_start);

#if HTTP_CLIENT_CONN_CACHE_SIZE > 0
        if (HTTP_ERR_SUCCESS != err)
        {
            DEBUG("HttpConn_%p cannot be cached: %s\n",
                  conn, "finished with error");
            goto release;
        }
        if (HTTP_CONNECTION_CLOSE == conn->response.headers.connection)
        {
            DEBUG("HttpConn_%p cannot be cached: %s\n",
                  conn, "\"Connection: close\" header received");
            goto release;
        }

        DEBUG("HttpClient_%p saving connection HttpConn_%p to cache...\n",
              client, conn);
        http_client_conn_cache_save(client, conn);
        conn = 0; // connection is taken

    release:
#endif // HTTP_CLIENT_CONN_CACHE_SIZE

        // release connection if it's not cached
        if (conn)
        {
            DEBUG("HttpClient_%p releasing connection HttpConn_%p...\n",
                  client, conn);
            http_conn_free(conn);
        }
    }

    return err;
}

#endif // HTTP client


// HTTP server
#if defined(HTTP_SERVER)

/*
 * http_server_new() implementation.
 */
int http_server_new(enum SSL_Proto proto, struct HTTP_Server **server_)
{
    TRACE("enter http_server_new(%s)\n", ssl_proto_string(proto));

    // select appropriate SSL protocol version
    WOLFSSL_METHOD *method = 0;
    switch (proto)
    {
    #ifdef WOLFSSL_ALLOW_SSLV3
        case SSL_PROTO_SSLv3:
            method = wolfSSLv3_server_method();
            break;
    #endif // WOLFSSL_ALLOW_SSLV3

    #ifdef WOLFSSL_ALLOW_TLSV10
        case SSL_PROTO_TLSv1_0:
            method = wolfTLSv1_server_method();
            break;
    #endif // WOLFSSL_ALLOW_TLSV10

        case SSL_PROTO_TLSv1_1:
            method = wolfTLSv1_1_server_method();
            break;

        case SSL_PROTO_TLSv1_2:
            method = wolfTLSv1_2_server_method();
            break;

    #ifdef WOLFSSL_TLS13
        case SSL_PROTO_TLSv1_3:
            method = wolfTLSv1_3_server_method();
            break;
    #endif // WOLFSSL_TLS13

        case SSL_PROTO_TLSv1_2_TO_SSLv3: // use highest possible version from SSLv3 to TLS 1.2
            method = wolfSSLv23_server_method();
            break;

        default:
            ERROR("\"%s\" is unknown or unsupported SSL protocol\n",
                  ssl_proto_string(proto));
            return HTTP_ERR_ILLEGAL; // failed
    }

    // allocate memory
    struct HTTP_Server *server = (struct HTTP_Server*)malloc(sizeof(*server));
    if (!server)
    {
        ERROR("http_server_new(): FAILED to allocate %d bytes of memory: (%d) %s\n",
              (int)sizeof(*server), errno, strerror(errno));
        return HTTP_ERR_NO_MEMORY; // failed
    }
    DEBUG("HttpServer_%p memory block of %d bytes allocated\n",
          server, (int)sizeof(*server));

    // default values
    server->endpoints = 0;      // no endpoints
    server->n_endpoints = 0;
    server->not_found_cb = 0;   // use default
    server->stopped = 0;
    server->fds = -1;
    server->fd = -1;
    server->ctx = 0;

    // create SSL context
    server->ctx = wolfSSL_CTX_new(method);
    if (!server->ctx)
    {
        ERROR("HttpServer_%p FAILED to create SSL context\n", server);
        http_server_free(server);
        return HTTP_ERR_FAILED; // failed
    }
    DEBUG("HttpServer_%p SSL context SSL_CTX_%p created\n", server, server->ctx);

    *server_ = server;
    TRACE("HttpServer_%p leave http_server_new()\n", server);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_server_free() implementation.
 */
void http_server_free(struct HTTP_Server *server)
{
    TRACE("HttpServer_%p enter http_server_free()\n", server);

    if (!server)
    {
        TRACE("nothing to release\n");
        return; // nothing to release
    }

    // release SSL context
    if (server->ctx)
    {
        DEBUG("HttpServer_%p releasing SSL_CTX_%p\n",
              server, server->ctx);
        wolfSSL_CTX_free(server->ctx);
        server->ctx = 0;
    }

    // release secure listen socket
    if (server->fds >= 0)
    {
        DEBUG("HttpServer_%p releasing secure listen socket_%d\n",
              server, server->fds);
        misc_closesocket(server->fds);
        server->fds = -1;
    }

    // release listen socket
    if (server->fd >= 0)
    {
        DEBUG("HttpServer_%p releasing listen socket_%d\n",
              server, server->fd);
        misc_closesocket(server->fd);
        server->fd = -1;
    }

    // release server
    DEBUG("HttpServer_%p releasing...\n", server);
    free(server);

    TRACE("HttpServer_%p leave http_server_free()\n", server);
}


/*
 * http_server_set_endpoints() implementation.
 */
void http_server_set_endpoints(struct HTTP_Server *server,
                               const struct HTTP_Endpoint *endpoints,
                               int num_of_endpoints)
{
    TRACE("HttpServer_%p enter http_server_set_endpoints(%p, %d)\n",
          server, endpoints, num_of_endpoints);

    server->endpoints = endpoints;
    server->n_endpoints = num_of_endpoints;

    INFO("HttpServer_%p use %d endpoints:\n",
         server, num_of_endpoints);
    for (int i = 0; i < num_of_endpoints; ++i)
    {
        INFO("  %10s %s\n",
             endpoints[i].methods,
             endpoints[i].uri_path);
        (void)i; // fake usage
    }

    TRACE("HttpServer_%p leave http_server_set_endpoints()\n", server);
}


/*
 * http_server_use_cert_file() implementation.
 */
int http_server_use_cert_file(struct HTTP_Server *server,
                              const char *cert_file,
                              const char *key_file)
{
    TRACE("HttpServer_%p enter http_server_use_cert_file(\"%s\", \"%s\")\n",
          server, cert_file, key_file);

#if defined(NO_FILESYSTEM)
    ERROR("HttpServer_%p no filesystem available to load certificate\n", server);
    return HTTP_ERR_ILLEGAL; // failed
#else

    if (cert_file)
    {
        // load server certificate into SSL context
        const int err = wolfSSL_CTX_use_certificate_file(server->ctx, cert_file,
                                                         WOLFSSL_FILETYPE_PEM);
        if (WOLFSSL_SUCCESS != err)
        {
            ERROR("HttpServer_%p FAILED to load \"%s\" certificate: %s\n",
                  server, cert_file, "please check file location or format");
            return HTTP_ERR_BAD_CERT; // failed
        }
        INFO("HttpServer_%p use certificate from \"%s\"\n", server, cert_file);
    }

    if (key_file)
    {
        // load server private key into SSL context
        const int err = wolfSSL_CTX_use_PrivateKey_file(server->ctx, key_file,
                                                        WOLFSSL_FILETYPE_PEM);
        if (WOLFSSL_SUCCESS != err)
        {
            ERROR("HttpServer_%p FAILED to load \"%s\" private key: %s\n",
                  server, key_file, "please check file location or format");
            return HTTP_ERR_BAD_PRIVATE_KEY; // failed
        }
        INFO("HttpServer_%p use private key from \"%s\"\n", server, key_file);
    }

    TRACE("HttpServer_%p leave http_server_use_cert_file()\n", server);
    return HTTP_ERR_SUCCESS; // OK
#endif // !NO_FILESYSTEM
}


/*
 * http_server_use_cert_asn1() implementation.
 */
int http_server_use_cert_asn1(struct HTTP_Server *server,
                              const void *cert, int cert_len,
                              const void *key, int key_len)
{
    TRACE("HttpServer_%p enter http_server_use_cert_asn1(%p, %d, %p, %d)\n",
          server, cert, cert_len, key, key_len);

    if (cert && cert_len)
    {
        // load server certificate into SSL context
        const int err = wolfSSL_CTX_use_certificate_buffer(server->ctx,
                                                           (const unsigned char*)cert,
                                                           (long)cert_len,
                                                           WOLFSSL_FILETYPE_ASN1);
        if (WOLFSSL_SUCCESS != err)
        {
            ERROR("HttpServer_%p FAILED to load certificate\n", server);
            return HTTP_ERR_BAD_CERT; // failed
        }
        INFO("HttpServer_%p use certificate from %d bytes buffer at %p\n",
             server, cert_len, cert);
    }

    if (key && key_len)
    {
        // load server private key into SSL context
        const int err = wolfSSL_CTX_use_PrivateKey_buffer(server->ctx,
                                                          (const unsigned char*)key,
                                                          (long)key_len,
                                                          WOLFSSL_FILETYPE_ASN1);
        if (WOLFSSL_SUCCESS != err)
        {
            ERROR("HttpServer_%p FAILED to load private key\n", server);
            return HTTP_ERR_BAD_PRIVATE_KEY; // failed
        }
        INFO("HttpServer_%p use private key from %d bytes buffer at %p\n",
             server, key_len, key);
    }

    TRACE("HttpServer_%p leave http_server_use_cert_asn()\n", server);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_server_set_cipher_list() implementation.
 */
int http_server_set_cipher_list(struct HTTP_Server *server,
                                const char *cipher_list)
{
    TRACE("HttpServer_%p enter http_server_set_cipher_list(\"%s\")\n", server, cipher_list);

    // set cipher list
    const int err = wolfSSL_CTX_set_cipher_list(server->ctx, cipher_list);
    if (WOLFSSL_SUCCESS != err)
    {
        ERROR("HttpServer_%p FAILED to set \"%s\" as cipher list\n",
              server, cipher_list);
        return HTTP_ERR_BAD_CIPHER_LIST; // failed
    }
    INFO("HttpServer_%p use the following ciphers: \"%s\"\n", server, cipher_list);

    TRACE("HttpServer_%p leave http_server_set_cipher_list()\n", server);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_server_start_secure() implementation.
 */
int http_server_start_secure(struct HTTP_Server *server,
                             int port, int backlog)
{
    TRACE("HttpServer_%p enter http_server_start_secure(%d, %d)\n",
          server, port, backlog);

    // already started?
    if (server->fds >= 0)
    {
        TRACE("already started\n");
        return HTTP_ERR_SUCCESS; // OK
    }

    // create listen socket
    server->fds = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fds < 0)
    {
        ERROR("HttpServer_%p FAILED to create listen socket for secure connections: (%d) %s\n",
              server, errno, strerror(errno));
        return HTTP_ERR_SOCKET; // failed
    }
    DEBUG("HttpServer_%p socket_%d is used as accept socket for secure connections\n",
          server, server->fds);

    // initialize server address (TODO: select interface address other than 0.0.0.0)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;          // IPv4
    addr.sin_addr.s_addr = INADDR_ANY;  // any for now
    addr.sin_port = port_h2n(port);

    // bind listen socket to our address
    if (!!bind(server->fds, (struct sockaddr*)&addr, sizeof(addr)))
    {
        ERROR("HttpServer_%p FAILED to bind to %d secure port: (%d) %s\n",
              server, port, errno, strerror(errno));
        return HTTP_ERR_BIND; // failed
    }

    // listen for new connections
    if (!!listen(server->fds, backlog))
    {
        ERROR("HttpServer_%p FAILED to listen on %d secure port: (%d) %s\n",
              server, port, errno, strerror(errno));
        return HTTP_ERR_LISTEN; // failed
    }

    INFO("HttpServer_%p listen on %d secure port (%d pending clients maximum)\n",
         server, port, backlog);

    TRACE("HttpServer_%p leave http_server_start_secure()\n", server);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_server_start() implementation.
 */
int http_server_start(struct HTTP_Server *server,
                      int port, int backlog)
{
    TRACE("HttpServer_%p enter http_server_start(%d, %d)\n",
          server, port, backlog);

    // already started?
    if (server->fd >= 0)
    {
        TRACE("already started\n");
        return HTTP_ERR_SUCCESS; // OK
    }

    // create listen socket
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0)
    {
        ERROR("HttpServer_%p FAILED to create listen socket for non-secure connections: (%d) %s\n",
              server, errno, strerror(errno));
        return HTTP_ERR_SOCKET; // failed
    }
    DEBUG("HttpServer_%p socket_%d is used as accept socket for non-secure connections\n",
          server, server->fd);

    // initialize server address (TODO: select interface address other than 0.0.0.0)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;          // IPv4
    addr.sin_addr.s_addr = INADDR_ANY;  // any for now
    addr.sin_port = port_h2n(port);

    // bind listen socket to our address
    if (!!bind(server->fd, (struct sockaddr*)&addr, sizeof(addr)))
    {
        ERROR("HttpServer_%p FAILED to bind to %d port: (%d) %s\n",
              server, port, errno, strerror(errno));
        return HTTP_ERR_BIND; // failed
    }

    // listen for new connections
    if (!!listen(server->fd, backlog))
    {
        ERROR("HttpServer_%p FAILED to listen on %d port: (%d) %s\n",
              server, port, errno, strerror(errno));
        return HTTP_ERR_LISTEN; // failed
    }

    INFO("HttpServer_%p listen on %d port (%d pending clients maximum)\n",
          server, port, backlog);

    TRACE("HttpServer_%p leave http_server_start()\n", server);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Find corresponding endpoint.
 * @param[in] server HTTP server.
 * @param[in] method Request HTTP method.
 * @param[in] uri Request URI.
 * @return Corresponding endpoint or `NULL` if not found.
 */
static const struct HTTP_Endpoint* http_server_find_endpoint(struct HTTP_Server *server,
                                                             enum HTTP_Method method,
                                                             const char *uri)
{
    // iterate over all available endpoints
    for (int i = 0; i < server->n_endpoints; ++i)
    {
        const struct HTTP_Endpoint *ep = &server->endpoints[i];

        // check request methods first, if present
        if (ep->methods && ep->methods[0]     // should not be empty
         && 0 != strcmp(ep->methods, "*"))    // should not be "*"
        {
            switch (method) {
            case HTTP_UNKNOWN_METHOD:
                break;

            case HTTP_GET:
                if (!strstr(ep->methods, "GET"))
                    continue; // goto next endpoint
                break;

            case HTTP_PUT:
                if (!strstr(ep->methods, "PUT"))
                    continue; // goto next endpoint
                break;

            case HTTP_POST:
                if (!strstr(ep->methods, "POST"))
                    continue; // goto next endpoint
                break;

            case HTTP_HEAD:
                if (!strstr(ep->methods, "HEAD"))
                    continue; // goto next endpoint
                break;

            case HTTP_DELETE:
                if (!strstr(ep->methods, "DELETE"))
                    continue; // goto next endpoint
                break;

            case HTTP_CONNECT:
                if (!strstr(ep->methods, "CONNECT"))
                    continue; // goto next endpoint
                break;

            case HTTP_OPTIONS:
                if (!strstr(ep->methods, "OPTIONS"))
                    continue; // goto next endpoint
                break;
            }
        }

        // check request URI
        if (!http_match_uri(ep->uri_path, uri))
            continue; // goto next endpoint

        return ep;
    }

    return 0; // not found
}


/**
 * @brief Handle HTTP request.
 * @param[in] server HTTP server.
 * @param[in] conn HTTP connection.
 * @return Zero on success.
 */
static int http_server_process(struct HTTP_Server *server,
                               struct HTTP_Conn *conn)
{
    TRACE("HttpServer_%p enter http_server_process(HttpConn_%p)\n", server, conn);

    // TODO: a few requests on the same connection until it is closed!
    // while (1) { http_conn_reset(conn); ... }

    DEBUG("HttpServer_%p try to receive request line from HttpConn_%p...\n", server, conn);
    const int err = http_conn_recv_request_line(conn);
    if (HTTP_ERR_SUCCESS != err)
        return err;

    // use the same HTTP protocol version as requested
    http_conn_set_response_proto(conn, conn->request.protocol);

    // find corresponding endpoint
    const struct HTTP_Endpoint *ep = http_server_find_endpoint(server,
                                                               conn->request.method,
                                                               http_conn_get_request_uri(conn));
    if (ep)
    {
        INFO("HttpServer_%p request \"%s %s\" matched to \"%s %s\" endpoint\n",
             server, http_conn_get_request_method(conn),
             http_conn_get_request_uri(conn),
             ep->methods, ep->uri_path);

        if (!ep->callback)
        {
            ERROR("HttpServer_%p no callback provided for \"%s %s\" endpoint\n",
                  server, ep->methods, ep->uri_path);
            return HTTP_ERR_FAILED; // failed
        }

        DEBUG("HttpServer_%p calling callback on HttpConn_%p\n", server, conn);
        const int err = ep->callback(HTTP_ERR_SUCCESS, conn, ep->user_data);
        if (HTTP_ERR_SUCCESS != err)
        {
            WARN("HttpServer_%p callback on HttpConn_%p failed: %d\n", server, conn, err);
            return err; // failed
        }
        DEBUG("HttpServer_%p callback on HttpConn_%p finished\n", server, conn);

        if (1) // flush, just in case
        {
            const int err = http_conn_flush_response(conn);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
        }
    }
    else
    {
        WARN("HttpServer_%p no endpoint found for \"%s %s\" request\n",
             server, http_conn_get_request_method(conn),
             http_conn_get_request_uri(conn));

        if (server->not_found_cb) // user defined NOT_FOUND
        {
            DEBUG("HttpServer_%p calling NOT_FOUND callback on HttpConn_%p\n", server, conn);
            const int err = server->not_found_cb(HTTP_ERR_SUCCESS, conn);
            if (HTTP_ERR_SUCCESS != err)
            {
                WARN("HttpServer_%p NOT_FOUND callback on HttpConn_%p failed: %d\n", server, conn, err);
                return err; // failed
            }
            DEBUG("HttpServer_%p NOT_FOUND callback on HttpConn_%p finished\n", server, conn);

            if (1) // flush, just in case
            {
                const int err = http_conn_flush_response(conn);
                if (HTTP_ERR_SUCCESS != err)
                    return err; // failed
            }
        }
        else // default NOT_FOUND callback
        {
            int err;
            http_conn_set_response_status(conn, HTTP_STATUS_NOT_FOUND);
            DEBUG("HttpServer_%p no NOT_FOUND callback found, just report %d status\n",
                 server, http_conn_get_response_status(conn));

            // close connection
            err = http_conn_send_response_header(conn, "Connection", "close");
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed

            // flush response
            err = http_conn_flush_response(conn);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
        }
    }

    TRACE("HttpServer_%p leave http_server_process()\n", server);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_server_main_loop() implementation.
 */
int http_server_main_loop(struct HTTP_Server *server)
{
    TRACE("HttpServer_%p enter http_server_main_loop()\n", server);
    INFO("HttpServer_%p waiting for a client connection...\n", server);

    // main "accept" loop
    while (!server->stopped)
    {
        int err;

        // poll timeout TODO: compile time constant
        TRACE("HttpServer_%p try to select incomming connection...\n", server);
        const int timeout_ms = 1000;
        int server_fd = -1; // actual server's socket
        int fds[] = {server->fds, server->fd};
        err = misc_select_read(fds, 2,
                               &server_fd,
                               timeout_ms);
        if (err < 0)
        {
            ERROR("HttpServer_%p FAILED to select incomming connection: (%d) %s\n",
                  server, errno, strerror(errno));
            return HTTP_ERR_ACCEPT; // failed
        }
        else if (0 == err || server_fd < 0)
        {
            // no connections yet, try again...
            TRACE("HttpServer_%p no connection yet, try again...\n", server);
            continue;
        }

        const uint32_t t_start = misc_time_ms();
        (void)t_start; // fake use

        // client address
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        socklen_t size = sizeof(addr);

        // accept client connections
        TRACE("HttpServer_%p accepting new connection...\n", server);
        int client_fd = accept(server_fd, (struct sockaddr*)&addr, &size);
        if (client_fd < 0)
        {
            WARN("HttpServer_%p FAILED to accept incomming connection: (%d) %s\n",
                 server, errno, strerror(errno));
            continue; // go to next client...
        }

        // make secure connection
        const int secure = (server_fd == server->fds);
        struct HTTP_Conn *conn = 0;
        err = http_conn_new(secure ? server->ctx : 0, client_fd, &conn);
        if (HTTP_ERR_SUCCESS != err)
        {
            WARN("HttpServer_%p FAILED to create %sconnection\n",
                 server, secure?"secure ":"");
            misc_closesocket(client_fd); // should be manually closed
            continue; // go to next client...
        }
        INFO("HttpServer_%p accept %sHttpConn_%p from %d.%d.%d.%d:%d\n",
             server, secure?"secure ":"", conn, PRINT_IPV4_ADDR_AND_PORT(addr));
        conn->remote_ipv4 = addr.sin_addr.s_addr;
        conn->remote_port = port_n2h(addr.sin_port);

        // do handshake
        if (conn->ssl)
        {
            TRACE("HttpServer_%p SSL handshaking on HttpConn_%p...\n", server, conn);
            err = wolfSSL_accept(conn->ssl);
            if (WOLFSSL_SUCCESS != err)
            {
                const int ssl_err = wolfSSL_get_error(conn->ssl, err);
                WARN("HttpServer_%p FAILED to do SSL handshake: (%d) %s\n",
                     server, ssl_err, wolfSSL_ERR_reason_error_string(ssl_err));
                http_conn_free(conn);
                continue; // go to next client
            }

            INFO("HttpConn_%p SSL handshake finished: %s\n", conn,
                 wolfSSL_get_version(conn->ssl));
        }

        // TODO: add connection to the list of server's connection
        // and do processing on dedicated thread!

        err = http_server_process(server, conn);
        if (HTTP_ERR_SUCCESS != err)
        {
            http_conn_free(conn);
            continue; // go to next client
        }

        // release connection
        INFO("HttpServer_%p request \"%s %s\" done with \"%d %s\" status in %d ms\n",
             server, http_conn_get_request_method(conn), http_conn_get_request_uri(conn),
             http_conn_get_response_status(conn), http_conn_get_response_reason(conn),
             misc_time_ms() - t_start);
        DEBUG("HttpServer_%p releasing HttpConn_%p\n", server, conn);
        http_conn_free(conn);
    }

    TRACE("HttpServer_%p leave http_server_main_loop()\n", server);
    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_server_stop() implementation.
 */
int http_server_stop(struct HTTP_Server *server)
{
    TRACE("HttpServer_%p enter http_server_stop()\n", server);
    server->stopped += 1;

    // TODO: stop and wait accept loop thread
    // TODO: stop and wait all connection threads

    TRACE("HttpServer_%p leave http_server_stop(%d)\n",
          server, server->stopped);
    return HTTP_ERR_SUCCESS; // OK
}

#endif // HTTP server


/*
 * http_parse_url() implementation.
 */
int http_parse_url(const char *url,
                   const char **proto, int *proto_len,
                   const char **host, int *host_len, int *port,
                   const char **path, int *path_len)
{
    // will be used to port auto-detection later
    const char *url_proto;
    int url_proto_len;

    // protocol
    const char *p = strstr(url, "://");
    if (p)
    {
        const int len = (p - url);
        url_proto = url;
        url_proto_len = len;
        url += len + 3; // ignore "://"
    }
    else
    {
        // fallback to https
        url_proto = "https";
        url_proto_len = 5;
    }
    if (proto) *proto = url_proto;
    if (proto_len) *proto_len = url_proto_len;

    // TODO: username and password

    // host
    if (*url)
    {
        const int len = strcspn(url, ":/?#");
        if (host) *host = url;
        if (host_len) *host_len = len;
        url += len;
    }
    else
    {
        if (host) *host = 0;
        if (host_len) *host_len = 0;
    }

    // port [optional]
    if (url[0] == ':')
    {
        char *end = 0;
        const int p = strtol(url+1, &end, 10);
        if (port) *port = p;
        url = end;
    }
    else if (port) // port auto-detection
    {
        if (5==url_proto_len && 0==strncmp(url_proto, "https", 5))
            *port = 443;
        else if (4==url_proto_len && 0==strncmp(url_proto, "http", 4))
            *port = 80;
        else if (3==url_proto_len && 0==strncmp(url_proto, "wss", 3))
            *port = 443;
        else if (2==url_proto_len && 0==strncmp(url_proto, "ws", 2))
            *port = 80;
        else if (3==url_proto_len && 0==strncmp(url_proto, "ftp", 3))
            *port = 21;
        else
        {
            // unknown protocol
            // keep *port as is
        }
    }

    // path
    if (url[0] == '/')
    {
        if (path) *path = url;
        if (path_len) *path_len = strlen(url);
    }
    else
    {
        if (path) *path = 0;
        if (path_len) *path_len = 0;
    }

    return HTTP_ERR_SUCCESS; // OK
}


/*
 * http_parse_query() implementation.
 */
int http_parse_query(const char **query_,
                     const char **name, int *name_len,
                     const char **value, int *value_len)
{
    const char *query = *query_;

    while (1) // do a few iterations
    {
        if (!query || !query[0]) // empty
            break; // no more data
        if ('#' == query[0]) // fragment
            break; // stop
        if ('&' == query[0])
        {
            query += 1; // skip '&'
            continue;
        }

        // get "name=value" length
        const int len = strcspn(query, "&#");
        const char *eq = (const char*)memchr(query, '=', len);
        if (eq) // name=value
        {
            if (name) *name = query;
            if (name_len) *name_len = (eq - query);
            if (value) *value = eq+1;
            if (value_len) *value_len = len - (eq-query) - 1;
        }
        else    // name only
        {
            if (name) *name = query;
            if (name_len) *name_len = len;
        }

        *query_ = query + len; // update state
        return HTTP_ERR_SUCCESS; // OK
    }

    *query_ = query; // update state
    return HTTP_ERR_NO_DATA; // no data
}


/*
 * http_get_query_param() implementation.
 */
int http_get_query_param(const char *query,
                         const char *name,
                         const char **value,
                         int *value_len)
{
    const char *q_name = 0;
    int q_name_len = 0;
    const char *q_val = 0;
    int q_val_len = 0;

    const int name_len = strlen(name);

    // iterate over all parameters
    while (HTTP_ERR_SUCCESS == http_parse_query(&query,
                                                &q_name, &q_name_len,
                                                &q_val,  &q_val_len))
    {
        // check the query parameter name
        if (q_name_len == name_len && 0 == memcmp(name, q_name, name_len))
        {
            if (value) *value = q_val;
            if (value_len) *value_len = q_val_len;
            return HTTP_ERR_SUCCESS; // OK
        }
    }

    return HTTP_ERR_NOT_FOUND; // not found
}


/*
 * http_match_uri() implementation.
 */
int http_match_uri(const char *pattern, const char *uri)
{
    const char *mp;
    const char *cp = 0;

    // iterate over URI and stop on query '?' or fragment '#'
    while (*uri && *uri != '?' && *uri != '#')
    {
        if (*pattern == '*')
        {
            ++pattern;
            if (!*pattern)
                return 1;
            mp = pattern;
            cp = uri + 1;
        }
        else if (*pattern == '?' || *pattern == *uri)
        {
            ++pattern;
            ++uri;
        }
        else if (!cp)
            return 0;
        else
        {
            pattern = mp;
            uri = cp++;
        }
    }

    while (*pattern == '*')
        ++pattern;

    return !*pattern;
}


/*
 * http_find_crlf() implementation.
 */
const void* http_find_crlf(const void *buf, int len)
{
    while (len > 0)
    {
        const uint8_t *p = (const uint8_t*)memchr(buf, '\r', len);
        if (!p)
        {
            break;
        }

        if (p[1] != '\n')
        {
            // '\r' found as a standalone symbol
            len -= p+1 - (const uint8_t*)buf;
            buf = p+1; // ignore '\r'
            continue;
        }

        return p; // found
    }

    return 0; // not found
}
