/**
 * @file
 * @brief HTTP client/server interface.
 * @author Sergey Polichnoy <pilatuz@gmail.com>
 */
#ifndef __HTTP_H__
#define __HTTP_H__

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#if defined(__cplusplus)
extern "C" {
#endif // __cplusplus

// connection working buffer size
#ifndef HTTP_CONN_BUF_SIZE
/**
 * @brief HTTP connection working buffer size.
 *
 * The same internal working buffer is used for sending and receiving purposes.
 * For HTTP client the request is prepared first, once request is sent the
 * response is received in the same buffer. For HTTP server the request is
 * received first, then response is prepared using the same buffer.
 *
 * Working buffer should be large enough to fit whole request line,
 * response status line and any request/response header line. If any of these
 * lines is bigger than working buffer size then the whole connection
 * will be failed with an error code.
 *
 * @relates HTTP_Client
 */
# define HTTP_CONN_BUF_SIZE (3816) // fallback to default connection buffer size
                                   // keep sizeof(HTTP_Conn) == 4096!
#elif HTTP_CONN_BUF_SIZE < 256
# error HTTP connection buffer too small!
#endif // HTTP_CONN_BUF_SIZE


// resolve cache size
#ifndef HTTP_RESOLVE_CACHE_SIZE
/**
 * @brief HTTP resolve cache size.
 *
 * This is the number of resolve cache entries in the HTTP client.
 * Each entry contains host name (or digest) and the IPv4 address.
 * If resolve cache entry already exists then no actual host resolving performed.
 *
 * Define as zero to disable cache.
 *
 * @see @ref resolve_cache
 * @relates HTTP_Client
 */
# define HTTP_RESOLVE_CACHE_SIZE (12) // fallback to default resolve cache size
                                      // keep sizeof(HTTP_Client) < 512!
#endif // HTTP_RESOLVE_CACHE_SIZE


// connection cache size
#ifndef HTTP_CLIENT_CONN_CACHE_SIZE
/**
 * @brief HTTP client connection cache size.
 *
 * This is the number of connection cache entries in the HTTP client.
 * Once request is completed the "keep-alive" connections are placed into
 * that cache to be reused later.
 *
 * Define as zero to disable cache.
 *
 * @see @ref connection_cache
 * @relates HTTP_Client
 */
# define HTTP_CLIENT_CONN_CACHE_SIZE (16) // fallback to default client connection cache size
#endif // HTTP_CLIENT_CONN_CACHE_SIZE


/**
 * @brief SSL protocol versions.
 *
 * One of these contants should be specified when HTTP_Client or HTTP_Server
 * is created. It is recommeded to use at least TLS v1.2.
 *
 * @see ssl_proto_string()
 * @see http_client_new()
 * @see http_server_new()
 */
enum SSL_Proto
{
#ifdef WOLFSSL_ALLOW_SSLV3
    SSL_PROTO_SSLv3,                /**< @brief SSL v3 (obsolete) */
#endif // WOLFSSL_ALLOW_SSLV3
#ifdef WOLFSSL_ALLOW_TLSV10
    SSL_PROTO_TLSv1_0,              /**< @brief TLS v1.0 (obsolete) */
#endif // WOLFSSL_ALLOW_TLSV10
    SSL_PROTO_TLSv1_1,              /**< @brief TLS v1.1 (obsolete) */
    SSL_PROTO_TLSv1_2,              /**< @brief TLS v1.2 */
#ifdef WOLFSSL_TLS13
    SSL_PROTO_TLSv1_3,              /**< @brief TLS v1.3 (draft) */
#endif // WOLFSSL_TLS13
    SSL_PROTO_TLSv1_2_TO_SSLv3      /**< @brief Any of TLS v1.2 to SSL v3 */
};


/**
 * @brief Get SSL protocol as string.
 *
 * If protocol is unknown then `"UNKNOWN"` is used as fallback.
 *
 * @param[in] proto One of SSL protocol.
 * @return String representation of SSL protocol.
 *
 * @see SSL_Proto
 */
const char* ssl_proto_string(enum SSL_Proto proto);


/**
 * @brief HTTP methods.
 *
 * With the HTTP_Client the HTTP method should be specified just before
 * sending the HTTP request line.
 *
 * @see http_method_string()
 * @see http_conn_get_request_method()
 * @see http_conn_set_request_method()
 * @see HTTP_Request
 */
enum HTTP_Method
{
    HTTP_UNKNOWN_METHOD = 0,    /**< @brief Unknown or unsupported HTTP method */
    HTTP_GET,                   /**< @brief `GET` HTTP method */
    HTTP_PUT,                   /**< @brief `PUT` HTTP method */
    HTTP_POST,                  /**< @brief `POST` HTTP method */
    HTTP_HEAD,                  /**< @brief `HEAD` HTTP method */
    HTTP_DELETE,                /**< @brief `DELETE` HTTP method */
    HTTP_CONNECT,               /**< @brief `CONNECT` HTTP method */
    HTTP_OPTIONS                /**< @brief `OPTIONS` HTTP method */
};


/**
 * @brief Get HTTP method as string.
 *
 * If method is unknown then `"UNKNOWN"` is used as fallback.
 *
 * @param[in] method One of HTTP method.
 * @return String representation of HTTP method.
 *
 * @see HTTP_Method
 */
const char* http_method_string(enum HTTP_Method method);


/**
 * @brief HTTP protocol versions.
 *
 * HTTP protocol should be specified in HTTP request line and in the
 * HTTP response status line.
 *
 * @see http_proto_string()
 * @see http_conn_get_request_proto()
 * @see http_conn_set_request_proto()
 * @see http_conn_get_response_proto()
 * @see http_conn_set_response_proto()
 * @see HTTP_Response
 * @see HTTP_Request
 */
enum HTTP_Proto
{
    HTTP_UNKNOWN_PROTO = 0,     /**< @brief Unknown or unsupported HTTP protocol */
    HTTP_PROTO_1_0 = 10,        /**< @brief `HTTP/1.0` protocol */
    HTTP_PROTO_1_1 = 11         /**< @brief `HTTP/1.1` protocol */
};


/**
 * @brief Get HTTP protocol version as string.
 *
 * If protocol version is unknown then `"UNKNOWN"` is used as fallback.
 *
 * @param[in] proto One of HTTP protocol version.
 * @return String representation of HTTP protocol version.
 *
 * @see HTTP_Proto
 */
const char* http_proto_string(enum HTTP_Proto proto);


/**
 * @brief HTTP status codes.
 *
 * A set of common HTTP status codes. Note not all codes are presented here.
 * This code is used in HTTP response status line.
 *
 * @see http_status_reason()
 * @see http_conn_get_response_status()
 * @see http_conn_set_response_status()
 * @see HTTP_Response
 */
enum HTTP_Status
{
    HTTP_STATUS_CONTINUE                = 100, /**< @brief 100 Continue. */

    HTTP_STATUS_OK                      = 200, /**< @brief 200 OK. */
    HTTP_STATUS_CREATED                 = 201, /**< @brief 201 Created. */
    HTTP_STATUS_ACCEPTED                = 202, /**< @brief 202 Accepted. */
    HTTP_STATUS_NO_CONTENT              = 204, /**< @brief 204 No Content. */
    HTTP_STATUS_RESET_CONTENT           = 205, /**< @brief 205 Reset Content. */
    HTTP_STATUS_PARTIAL_CONTENT         = 206, /**< @brief 206 Partial Content. */

    HTTP_STATUS_MOVED_PERMANENTLY       = 301, /**< @brief 301 Moved Permanently. */
    HTTP_STATUS_FOUND                   = 302, /**< @brief 302 Found. */
    HTTP_STATUS_NOT_MODIFIED            = 304, /**< @brief 304 Not Modified. */

    HTTP_STATUS_BAD_REQUEST             = 400, /**< @brief 400 Bad Request. */
    HTTP_STATUS_UNAUTHORIZED            = 401, /**< @brief 401 Unauthorized. */
    HTTP_STATUS_FORBIDDEN               = 403, /**< @brief 403 Forbidden. */
    HTTP_STATUS_NOT_FOUND               = 404, /**< @brief 404 Not Found. */
    HTTP_STATUS_METHOD_NOT_ALLOWED      = 405, /**< @brief 405 Method Not Allowed. */
    HTTP_STATUS_NOT_ACCEPTABLE          = 406, /**< @brief 406 Not Acceptable. */
    HTTP_STATUS_REQUEST_TIMEOUT         = 408, /**< @brief 408 Request Timeout. */

    HTTP_STATUS_INTERNAL_SERVER_ERROR   = 500, /**< @brief 500 Internal Server Error. */
    HTTP_STATUS_NOT_IMPLEMENTED         = 501, /**< @brief 501 Not Implemented. */
    HTTP_STATUS_SERVICE_UNAVAILABLE     = 503  /**< @brief 503 Service Unavailable. */
};


/**
 * @brief Get default reason phrase for HTTP status.
 * @param[in] status HTTP status.
 * @return Reason phrase or `NULL` if status is unknown.
 *
 * @see HTTP_Status
 */
const char* http_status_reason(int status);


/**
 * @brief HTTP error codes.
 *
 * Set of error codes that can be reported by this library functions.
 */
enum HTTP_Error
{
    // generic
    HTTP_ERR_SUCCESS    =  0,   /**< @brief No error */
    HTTP_ERR_FAILED     = -1,   /**< @brief Generic failure */
    HTTP_ERR_ILLEGAL    = -2,   /**< @brief Illegel usage */
    HTTP_ERR_NO_MEMORY  = -3,   /**< @brief No memory available */
    HTTP_ERR_READ       = -4,   /**< @brief Read/receive error */
    HTTP_ERR_WRITE      = -5,   /**< @brief Write/send error */
    HTTP_ERR_SOCKET     = -6,   /**< @brief Socket error */
    HTTP_ERR_BIND       = -7,   /**< @brief Bind error */
    HTTP_ERR_ACCEPT     = -8,   /**< @brief Accept error */
    HTTP_ERR_LISTEN     = -9,   /**< @brief Listen error */
    HTTP_ERR_CONNECT    = -10,  /**< @brief Connect error */
    HTTP_ERR_RESOLVE    = -11,  /**< @brief Resolve error */
    HTTP_ERR_HANDSHAKE  = -12,  /**< @brief Handshake error */
    HTTP_ERR_NO_DATA    = -13,  /**< @brief No data error */
    HTTP_ERR_NOT_FOUND  = -14,  /**< @brief Not found error */

    // common
    HTTP_ERR_BAD_CERT               = -101, /**< @brief Bad certificate */
    HTTP_ERR_BAD_PRIVATE_KEY        = -102, /**< @brief Bad private key */
    HTTP_ERR_BAD_CIPHER_LIST        = -103, /**< @brief Bad cipher list */
    HTTP_ERR_BAD_URL_NO_PORT        = -104, /**< @brief Bad URL: no port */
    HTTP_ERR_BAD_URL_NO_HOST        = -105, /**< @brief Bad URL: no host */
    HTTP_ERR_BAD_URL_NO_URI         = -106, /**< @brief Bad URL: no URI path */
    HTTP_ERR_BAD_URL_PROTOCOL       = -107, /**< @brief Bad URL protocol */
    HTTP_ERR_BAD_HEADER_NO_COLON    = -108, /**< @brief No header colon */
    HTTP_ERR_BAD_CHUNK_NO_LENGTH    = -109, /**< @brief No chunk length */

    // request/response
    HTTP_ERR_BAD_REQUEST_NO_METHOD      = -200, /**< @brief Bad request: no method */
    HTTP_ERR_BAD_REQUEST_NO_URI         = -201, /**< @brief Bad request: no URI */
    HTTP_ERR_BAD_RESPONSE_NO_PROTOCOL   = -210, /**< @brief Bad response: no protocol */
    HTTP_ERR_BAD_RESPONSE_NO_STATUS     = -211  /**< @brief Bad response: no status */
};


/**
 * @brief Connection flags.
 *
 * This constants are related to various connection aspects:
 *
 * - HTTP_CONN_DO_NOT_CACHE flag is used to prevent connection caching.
 *   It is equivalent to "Connection: close" header.
 * - HTTP_CONN_NO_THREAD means to run request on the same thread.
 * - HTTP_CONN_CHECK_DOMAIN_NAME flag enables domain name check during SSL handshake.
 * - HTTP_CONN_USE_SNI flag enables SNI TLS extension.
 *
 * @see http_client_do()
 */
enum HTTP_ConnFlags
{
    HTTP_CONN_DO_NOT_CACHE      = 0x0001, /**< @brief Do not cache connection after use */
    HTTP_CONN_NO_THREAD         = 0x0002, /**< @brief Do not run additional thread */
    HTTP_CONN_CHECK_DOMAIN_NAME = 0x0010, /**< @brief Check domain name during SSL handshake */
    HTTP_CONN_USE_SNI           = 0x0020  /**< @brief Use Server Name Indication TLS extension */
};


/**
 * @brief Possible values of "Connection" header.
 *
 * @see http_header_connection_parse()
 * @see http_header_connection_string()
 */
enum HTTP_HeaderConnection
{
    HTTP_CONNECTION_MISSING,    /**< @brief Header is missing. */
    HTTP_CONNECTION_UNKNOWN,    /**< @brief Unknown value. */
    HTTP_CONNECTION_KEEP_ALIVE, /**< @brief Connection should be kept alive. */
    HTTP_CONNECTION_CLOSE       /**< @brief Connection should be closed. */
};


/**
 * @brief Parse the "Connection" header.
 * @param value Connection value as string.
 * @return Parsed Connection value.
 * @see HTTP_HeaderConnection
 */
enum HTTP_HeaderConnection http_header_connection_parse(const char *value);


/**
 * @brief Get "Connection" header as a string.
 * @param connection Connection value.
 * @return Connection value as string.
 *         "unknown" for unknown values.
 * @see HTTP_HeaderConnection
 */
const char* http_header_connection_string(enum HTTP_HeaderConnection connection);


/**
 * @brief Possible values of "Transfer-Encoding" header.
 *
 * @see http_header_transfer_encoding_parse()
 * @see http_header_transfer_encoding_string()
 */
enum HTTP_HeaderTransferEncoding
{
    HTTP_TRANSFER_ENCODING_MISSING, /**< @brief Header is missing. */
    HTTP_TRANSFER_ENCODING_UNKNOWN, /**< @brief Unknown value. */
    HTTP_TRANSFER_ENCODING_CHUNKED  /**< @brief Chunked transfer encoding. */
};


/**
 * @brief Parse the "Transfer-Encoding" header.
 * @param value Transfer-Encoding value as string.
 * @return Parsed Transfer-Encoding value.
 * @see HTTP_HeaderTransferEncoding
 */
enum HTTP_HeaderTransferEncoding http_header_transfer_encoding_parse(const char *value);


/**
 * @brief Get "Transfer-Encoding" header as a string.
 * @param transfer_encoding Transfer-Encoding value.
 * @return Transfer-Encoding value as string.
 *         "unknown" for unknown values.
 * @see HTTP_HeaderTransferEncoding
 */
const char* http_header_transfer_encoding_string(enum HTTP_HeaderTransferEncoding transfer_encoding);


// HTTP connection
#if defined(HTTP_CLIENT) || defined(HTTP_SERVER)

/**
 * @brief HTTP request related data.
 *
 * Contain request line related data: HTTP method, HTTP protocol and URI.
 * Also contains target host and a set of known headers:
 * - "Content-Length" as `headers.content_length`
 * - "Connection" as `headers.connection`
 *
 * If URI is short enough to fit the `uri_fix` array
 * then no dynamic memory is used. Otherwise the dynamic
 * buffer `uri_dyn` is allocated to store long string.
 *
 * The same approach is used for `host_dyn` and `host_fix`.
 *
 * @see http_conn_get_request_uri()
 * @see http_conn_set_request_uri()
 * @see http_conn_get_request_host()
 * @see http_conn_set_request_host()
 * @relates HTTP_Conn
 */
struct HTTP_Request
{
    /**
     * @brief HTTP method.
     *
     * Zero if unknown.
     */
    enum HTTP_Method method;

    /**
     * @brief Protocol version.
     *
     * Zero if unknown.
     */
    enum HTTP_Proto protocol;

    /**
     * @brief Resource identifier.
     *
     * Dynamically allocated.
     */
    char *uri_dyn;

    /**
     * @brief Resource identifier (static).
     */
    char uri_fix[96];

    /**
     * @brief Target host.
     *
     * Dynamically allocated.
     */
    char *host_dyn;

    /**
     * @brief Target host (static).
     */
    char host_fix[32];

    // set of known headers
    struct
    {
        /**
         * @brief The "Content-Length" header.
         *
         * `-1` if corresponding header is missing.
         */
        int64_t content_length;

        /**
         * @brief The "Connection" header.
         */
        enum HTTP_HeaderConnection connection;

        /**
         * @brief The "Transfer-Encoding" header.
         */
        enum HTTP_HeaderTransferEncoding transfer_encoding;
    } headers;
    /**<
     * @brief Set of known request headers.
     */
};


/**
 * @brief HTTP response related data.
 *
 * Contain response status line related data: HTTP protocol, status code and
 * reason phrase. Also contains a set of known headers:
 * - "Content-Length" as `headers.content_length`
 * - "Connection" as `headers.connection`
 *
 * If reason phrase is short enough to fit the `reason_fix` array
 * then no dynamic memory is used. Otherwise the dynamic
 * buffer `reason_dyn` is allocated to store long string.
 *
 * @see http_conn_get_response_reason()
 * @see http_conn_set_response_reason()
 * @relates HTTP_Conn
 */
struct HTTP_Response
{
    /**
     * @brief Protocol version.
     *
     * Zero if unknown.
     */
    enum HTTP_Proto protocol;

    /**
     * @brief HTTP status code.
     *
     * Zero if unknown.
     */
    int status;

    /**
     * @brief Status reason phrase.
     *
     * Dynamically allocated.
     */
    char *reason_dyn;

    /**
     * @brief Status reason phrase (static).
     */
    char reason_fix[32];

    // set of known headers
    struct
    {
        /**
         * @brief The "Content-Length" header.
         *
         * `-1` if corresponding header is missing.
         */
        int64_t content_length;

        /**
         * @brief The "Connection" header.
         */
        enum HTTP_HeaderConnection connection;

        /**
         * @brief The "Transfer-Encoding" header.
         */
        enum HTTP_HeaderTransferEncoding transfer_encoding;
    } headers;
    /**<
     * @brief Set of known response headers.
     */
};


/**
 * @brief HTTP connection.
 *
 * Manages one client or server HTTP connection.
 * Contains request and response releated data
 * and internal working buffer.
 *
 * @see http_conn_new()
 * @see http_conn_free()
 */
struct HTTP_Conn
{
    /**
     * @brief Socket file descriptor.
     */
    int fd;

    /**
     * @brief Secure stream or `NULL`.
     */
    WOLFSSL *ssl;

    /**
     * @brief Destination or source IPv4 address.
     */
    uint32_t remote_ipv4;

    /**
     * @brief Destination or source port number.
     */
    uint16_t remote_port;


    /**
     * @brief Request related data.
     */
    struct HTTP_Request request;

    /**
     * @brief Response related data.
     */
    struct HTTP_Response response;


    /**
     * @brief Internally used data.
     *
     * Contains working buffer and related flags.
     */
    struct HTTP_ConnInternal
    {
        /**
         * @brief Working buffer.
         *
         * This buffer is used for recv/send operations.
         */
        uint8_t buf[HTTP_CONN_BUF_SIZE];

        /**
         * @brief Working buffer read position.
         */
        int buf_pos;

        /**
         * @brief Actual working buffer length in bytes.
         */
        int buf_len;

        /**
         * @brief Request/response flags.
         */
        uint32_t flags;

        /**
         * @brief Actual number of bytes already read from content.
         *
         * Used with `request.content_length` or `response.content_length`.
         * Also will be used for "chunked" transfer.
         */
        int64_t content_pos;
    } internal; /**< @brief Internal data. */
};


/**
 * @brief Create new HTTP connection.
 *
 * The socket is managed by new HTTP connection and
 * will be closed automatically when connection is gone.
 * If this function fails then underlying socket
 * should be closed manually.
 *
 * @param[in] ctx SSL context to create connection in.
 *                For insecure connections (plain http) just use `NULL` here.
 * @param[in] fd Client socket file descriptor.
 * @param[out] conn New HTTP connection.
 * @return Zero on success.
 *
 * @see http_conn_free()
 * @relates HTTP_Conn
 */
int http_conn_new(WOLFSSL_CTX *ctx, int fd,
                  struct HTTP_Conn **conn);


/**
 * @brief Release HTTP connection and all owned resources.
 * @param[in] conn Connection to release.
 *
 * @see http_conn_new()
 * @relates HTTP_Conn
 */
void http_conn_free(struct HTTP_Conn *conn);


/**
 * @brief Get HTTP request method as string.
 * @param[in] conn Connection to get method of.
 * @return Request method string.
 *
 * @see http_conn_set_request_method()
 * @relates HTTP_Conn
 */
static inline const char* http_conn_get_request_method(const struct HTTP_Conn *conn)
{
    return http_method_string(conn->request.method);
}


/**
 * @brief Set HTTP request method.
 * @param[in] conn Connection to set method for.
 * @param[in] method HTTP request method.
 * @return Zero on success.
 *
 * @see http_conn_get_request_method()
 * @relates HTTP_Conn
 */
int http_conn_set_request_method(struct HTTP_Conn *conn, enum HTTP_Method method);


/**
 * @brief Get HTTP request protocol as string.
 * @param[in] conn Connection to get protocol of.
 * @return Request protocol string.
 *
 * @see http_conn_set_request_proto()
 * @relates HTTP_Conn
 */
static inline const char* http_conn_get_request_proto(const struct HTTP_Conn *conn)
{
    return http_proto_string(conn->request.protocol);
}


/**
 * @brief Set HTTP request protocol.
 * @param[in] conn Connection to set protocol for.
 * @param[in] proto HTTP protocol.
 * @return Zero on success.
 *
 * @see http_conn_get_request_proto()
 * @relates HTTP_Conn
 */
int http_conn_set_request_proto(struct HTTP_Conn *conn, enum HTTP_Proto proto);


/**
 * @brief Get HTTP request URI.
 * @param[in] conn Connection to get URI of.
 * @return Request URI.
 *
 * @see http_conn_set_request_uri()
 * @see http_conn_add_request_uri()
 * @relates HTTP_Conn
 */
static inline const char* http_conn_get_request_uri(const struct HTTP_Conn *conn)
{
    return conn->request.uri_dyn ? conn->request.uri_dyn    // dynamic
                                 : conn->request.uri_fix;   // fixed
}


/**
 * @brief Set HTTP request URI.
 * @param[in] conn Connection to set URI of.
 * @param[in] uri Request URI.
 * @param[in] uri_len Request URI length in bytes.
 *                    `-1` if string is NULL-terminated.
 * @return Zero on success.
 *
 * @see http_conn_get_request_uri()
 * @see http_conn_add_request_uri()
 * @relates HTTP_Conn
 */
int http_conn_set_request_uri(struct HTTP_Conn *conn,
                              const char *uri,
                              int uri_len);


/**
 * @brief Add a part of HTTP request URI to the end.
 * @param[in] conn Connection to update URI of.
 * @param[in] uri_part Request URI part to add.
 * @return Zero on success.
 *
 * @see http_conn_get_request_uri()
 * @see http_conn_set_request_uri()
 * @relates HTTP_Conn
 */
int http_conn_add_request_uri(struct HTTP_Conn *conn,
                              const char *uri_part);


/**
 * @brief Get HTTP request target host.
 * @param[in] conn Connection to get host of.
 * @return Target host.
 *
 * @see http_conn_set_request_host()
 * @relates HTTP_Conn
 */
static inline const char* http_conn_get_request_host(const struct HTTP_Conn *conn)
{
    return conn->request.host_dyn ? conn->request.host_dyn  // dynamic
                                  : conn->request.host_fix; // fixed
}


/**
 * @brief Set HTTP request target host.
 * @param[in] conn Connection to set host of.
 * @param[in] host Target host.
 * @param[in] host_len Target host length in bytes.
 *                     `-1` if string is NULL-terminated.
 * @return Zero on success.
 *
 * @see http_conn_get_request_host()
 * @relates HTTP_Conn
 */
int http_conn_set_request_host(struct HTTP_Conn *conn,
                               const char *host,
                               int host_len);


/**
 * @brief Check if HTTP request is chunked.
 * @param[in] conn Connection to check.
 * @return Non-zero if request is chunked.
 *
 * @relates HTTP_Conn
 */
static inline int http_conn_is_request_chunked(const struct HTTP_Conn *conn)
{
    return (HTTP_TRANSFER_ENCODING_CHUNKED == conn->request.headers.transfer_encoding);
}


/**
 * @brief Get remaining length of HTTP request content.
 *
 * Note, this value contains number of remaining bytes in the request's
 * content. If the "Transfer-Encoding: chunked" mode is used then
 * this value contains remaining length of the current data chunk.
 *
 * @param conn Connection to check.
 * @return Number of bytes can be received on next iteration.
 */
static inline int http_conn_request_content_can_recv(const struct HTTP_Conn *conn)
{
    if (conn->request.headers.content_length >= 0)
    {
        const int64_t rem = (conn->request.headers.content_length - conn->internal.content_pos);
        return rem >= 0 ? (int)rem : 0; // TODO: check overflow
    }

    return 0; // we don't know how much can be received
}


/**
 * @brief Get HTTP response protocol as string.
 * @param conn Connection to get protocol of.
 * @return Response protocol string.
 *
 * @see http_conn_set_response_proto()
 * @relates HTTP_Conn
 */
static inline const char* http_conn_get_response_proto(const struct HTTP_Conn *conn)
{
    return http_proto_string(conn->response.protocol);
}


/**
 * @brief Set HTTP response protocol.
 * @param[in] conn Connection to set protocol for.
 * @param[in] proto HTTP protocol.
 * @return Zero on success.
 *
 * @see http_conn_get_response_proto()
 * @relates HTTP_Conn
 */
int http_conn_set_response_proto(struct HTTP_Conn *conn, enum HTTP_Proto proto);



/**
 * @brief Get HTTP response status code.
 * @param[in] conn Connection to get status code of.
 * @return Response status code.
 *
 * @see http_conn_set_response_status()
 * @relates HTTP_Conn
 */
static inline int http_conn_get_response_status(const struct HTTP_Conn *conn)
{
    return conn->response.status;
}


/**
 * @brief Set HTTP response status code.
 * @param[in] conn Connection to set status code for.
 * @param[in] status HTTP status code.
 * @return Zero on success.
 *
 * @see http_conn_get_response_status()
 * @relates HTTP_Conn
 */
int http_conn_set_response_status(struct HTTP_Conn *conn, int status);


/**
 * @brief Get HTTP response reason phrase.
 * @param[in] conn Connection to get reason phrase of.
 * @return Reason phrase.
 *
 * @see http_conn_set_response_reason()
 * @relates HTTP_Conn
 */
static inline const char* http_conn_get_response_reason(const struct HTTP_Conn *conn)
{
    const char *reason = conn->response.reason_dyn ? conn->response.reason_dyn  // dynamic
                                                   : conn->response.reason_fix; // fixed

    if (!reason || !reason[0]) // empty?
    {
        // try to use default reason phrase
        const char *default_reason = http_status_reason(conn->response.status);
        if (default_reason)
            reason = default_reason;
    }

    return reason; // still might be empty for unknown status
}


/**
 * @brief Set HTTP response reason phrase.
 * @param[in] conn Connection to set reason phrase of.
 * @param[in] reason Reason phrase.
 * @param[in] reason_len Reason phrase length in bytes.
 *                       `-1` if string is NULL-terminated.
 * @return Zero on success.
 *
 * @see http_conn_get_response_status()
 * @see http_conn_get_response_reason()
 * @relates HTTP_Conn
 */
int http_conn_set_response_reason(struct HTTP_Conn *conn,
                                  const char *reason,
                                  int reason_len);


/**
 * @brief Check if HTTP response is chunked.
 * @param[in] conn Connection to check.
 * @return Non-zero if response is chunked.
 *
 * @relates HTTP_Conn
 */
static inline int http_conn_is_response_chunked(const struct HTTP_Conn *conn)
{
    return (HTTP_TRANSFER_ENCODING_CHUNKED == conn->response.headers.transfer_encoding);
}


/**
 * @brief Get remaining length of HTTP response content.
 *
 * Note, this value contains number of remaining bytes in the response's
 * content. If the "Transfer-Encoding: chunked" mode is used then
 * this value contains remaining length of the current data chunk.
 *
 * @param conn Connection to check.
 * @return Number of bytes can be received on next iteration.
 */
static inline int http_conn_response_content_can_recv(const struct HTTP_Conn *conn)
{
    if (conn->response.headers.content_length >= 0)
    {
        const int64_t rem = (conn->response.headers.content_length - conn->internal.content_pos);
        return rem >= 0 ? (int)rem : 0; // TODO: check overflow
    }

    return 0; // we don't know how much can be received
}


// HTTP connection - client related
#if defined(HTTP_CLIENT)

/**
 * @brief Send HTTP request line to the working buffer.
 *
 * Request line "METHOD URI PROTOCOL" will be saved
 * to the internal working buffer.
 * If there is no available space in the buffer then
 * buffer will be sent to the underlying socket first.
 * Usually working buffer should be empty
 * because this is the first operation.
 *
 * It is illegal to call this operation more than one time.
 *
 * @param[in] conn Connection to send request line to.
 * @return Zero on success.
 *
 * @see http_conn_send_request_header()
 * @see http_conn_send_request_body()
 * @see http_conn_flush_request()
 * @relates HTTP_Conn
 */
int http_conn_send_request_line(struct HTTP_Conn *conn);


/**
 * @brief Send custom HTTP request header.
 *
 * Header name and it's value will be written to internal buffer.
 * If there is no available space in the buffer then
 * buffer will be sent to the underlying socket first.
 *
 * It is illegal to call this operation after body or flush.
 *
 * @param[in] conn Connection to send request header to.
 * @param[in] name Header name.
 * @param[in] value Header value.
 * @return Zero on success.
 *
 * @see http_conn_send_request_line()
 * @see http_conn_send_request_body()
 * @see http_conn_flush_request()
 * @relates HTTP_Conn
 */
int http_conn_send_request_header(struct HTTP_Conn *conn,
                                  const char *name,
                                  const char *value);


/**
 * @brief Send custom HTTP request body.
 *
 * Request body will be written to internal buffer.
 * If there is no available space in the buffer then
 * buffer will be sent to the underlying socket first.
 *
 * It is illegal to call this operation after flush.

 * @param[in] conn Connection to send request body to.
 * @param[in] buf Request body.
 * @param[in] len Request body length in bytes.
 * @return Zero on success.
 *
 * @see http_conn_send_request_line()
 * @see http_conn_send_request_header()
 * @see http_conn_flush_request()
 * @relates HTTP_Conn
 */
int http_conn_send_request_body(struct HTTP_Conn *conn,
                                const void *buf, int len);

/**
 * @brief Finish request sending.
 *
 * This function sends all remainging data from
 * internal buffer to the underlying socket.
 *
 * @param[in] conn Connection to finish request.
 * @return Zero on success.
 *
 * @see http_conn_send_request_line()
 * @see http_conn_send_request_header()
 * @see http_conn_send_request_body()
 * @relates HTTP_Conn
 */
int http_conn_flush_request(struct HTTP_Conn *conn);


/**
 * @brief Receive HTTP response status line.
 *
 * This function receives HTTP status line and updates
 * corresponding connection fields:
 * - `response.status`
 * - `response.reason`
 * - `response.protocol`
 *
 * This function should be called first on receiving HTTP response.
 * It is illegal to call this function after header or body.
 *
 * @param[in] conn Connection to receive HTTP status from.
 * @return Zero on success.
 *
 * @see http_conn_recv_response_header()
 * @see http_conn_recv_response_body()
 * @see http_conn_ignore_response_headers()
 * @see http_conn_ignore_response_body()
 * @relates HTTP_Conn
 */
int http_conn_recv_response_status(struct HTTP_Conn *conn);


/**
 * @brief Receive HTTP response header.
 *
 * The header name and value are NULL-terminated strings but
 * these pointers are valid only until next `http_conn_recv_*` call.
 * So if you need to use these values later do a deep copy.
 *
 * If there is no more HTTP header in the response, then
 * both name and value are set to `NULL`.
 *
 * @param[in] conn Connection to receive HTTP header from.
 * @param[out] name Header name.
 * @param[out] value Header value.
 * @return Zero on success.
 *
 * @see http_conn_recv_response_status()
 * @see http_conn_recv_response_body()
 * @see http_conn_ignore_response_headers()
 * @see http_conn_ignore_response_body()
 * @relates HTTP_Conn
 */
int http_conn_recv_response_header(struct HTTP_Conn *conn,
                                   const char **name,
                                   const char **value);


/**
 * @brief Ignore rest of HTTP headers.
 * @param[in] conn Connection to receive HTTP headers from.
 * @return Zero on success.
 *
 * @see http_conn_recv_response_status()
 * @see http_conn_recv_response_header()
 * @see http_conn_recv_response_body()
 * @see http_conn_ignore_response_body()
 * @relates HTTP_Conn
 */
int http_conn_ignore_response_headers(struct HTTP_Conn *conn);


/**
 * @brief Receive HTTP response body.
 * @param[in] conn Connection to receive data from.
 * @param[in] buf Buffer to store received data.
 * @param[in,out] len Buffer length in bytes on input.
 *                    Actual number of bytes read on output.
 * @return Zero on success.
 *
 * @see http_conn_recv_response_status()
 * @see http_conn_recv_response_header()
 * @see http_conn_ignore_response_headers()
 * @see http_conn_ignore_response_body()
 * @relates HTTP_Conn
 */
int http_conn_recv_response_body(struct HTTP_Conn *conn,
                                 void *buf, int *len);


/**
 * @brief Ignore rest of HTTP response body.
 *
 * If `Content-Length` header is known then ignore exactly specified
 * number of bytes. Otherwise ignores all data until connection is closed.
 *
 * @param[in] conn Connection to receive data from.
 * @return Zero on success.
 *
 * @see http_conn_recv_response_status()
 * @see http_conn_recv_response_header()
 * @see http_conn_ignore_response_headers()
 * @see http_conn_recv_response_body()
 * @relates HTTP_Conn
 */
int http_conn_ignore_response_body(struct HTTP_Conn *conn);

#endif // HTTP connection - client related


// HTTP connection - server related
#if defined(HTTP_SERVER)

/**
 * @brief Receive HTTP request line.
 *
 * This function receives HTTP request line and updates
 * corresponding connection fields:
 * - `request.method`
 * - `request.uri`
 * - `request.protocol`
 *
 * This function should be called first on receiving HTTP request.
 * It is illegal to call this function after header or body.
 *
 * @param[in] conn Connection to receive HTTP request from.
 * @return Zero on success.
 *
 * @see http_conn_recv_request_header()
 * @see http_conn_ignore_request_headers()
 * @see http_conn_recv_request_body()
 * @see http_conn_ignore_request_body()
 * @relates HTTP_Conn
 */
int http_conn_recv_request_line(struct HTTP_Conn *conn);


/**
 * @brief Receive HTTP request header.
 *
 * The header name and value are NULL-terminated strings but
 * these pointers are valid only until next `http_conn_recv_*` call.
 * So if you need to use these values later do a deep copy.
 *
 * If there is no more HTTP header in the request, then
 * both name and value are set to `NULL`.
 *
 * @param[in] conn Connection to receive HTTP header from.
 * @param[out] name Header name.
 * @param[out] value Header value.
 * @return Zero on success.
 *
 * @see http_conn_recv_request_line()
 * @see http_conn_ignore_request_headers()
 * @see http_conn_recv_request_body()
 * @see http_conn_ignore_request_body()
 * @relates HTTP_Conn
 */
int http_conn_recv_request_header(struct HTTP_Conn *conn,
                                  const char **name,
                                  const char **value);


/**
 * @brief Ignore rest of HTTP headers.
 * @param[in] conn Connection to receive HTTP headers from.
 * @return Zero on success.
 *
 * @see http_conn_recv_request_line()
 * @see http_conn_recv_request_header()
 * @see http_conn_recv_request_body()
 * @see http_conn_ignore_request_body()
 * @relates HTTP_Conn
 */
int http_conn_ignore_request_headers(struct HTTP_Conn *conn);


/**
 * @brief Receive HTTP request body.
 * @param[in] conn Connection to receive data from.
 * @param[in] buf Buffer to store received data.
 * @param[in,out] len Buffer length in bytes on input.
 *                    Actual number of bytes read on output.
 * @return Zero on success.
 *
 * @see http_conn_recv_request_line()
 * @see http_conn_recv_request_header()
 * @see http_conn_ignore_request_headers()
 * @see http_conn_ignore_request_body()
 * @relates HTTP_Conn
 */
int http_conn_recv_request_body(struct HTTP_Conn *conn,
                                void *buf, int *len);


/**
 * @brief Ignore rest of HTTP request body.
 *
 * If `Content-Length` header is known then ignore exactly specified
 * number of bytes.
 *
 * @param[in] conn Connection to receive data from.
 * @return Zero on success.
 *
 * @see http_conn_recv_request_line()
 * @see http_conn_recv_request_header()
 * @see http_conn_ignore_request_headers()
 * @see http_conn_recv_request_body()
 * @relates HTTP_Conn
 */
int http_conn_ignore_request_body(struct HTTP_Conn *conn);


/**
 * @brief Save HTTP response line to the working buffer.
 *
 * Response line "PROTOCOL STATUS REASON" will be saved
 * to the internal working buffer.
 * If there is no available space in the buffer then
 * buffer will be sent to the underlying socket first.
 * Usually working buffer should be empty
 * because this is the first operation.
 *
 * It is illegal to call this operation more than one time.
 *
 * @param[in] conn Connection to send response status line to.
 * @return Zero on success.
 *
 * @see http_conn_send_response_header()
 * @see http_conn_send_response_body()
 * @see http_conn_flush_response()
 * @relates HTTP_Conn
 */
int http_conn_send_response_status(struct HTTP_Conn *conn);


/**
 * @brief Send custom HTTP response header.
 *
 * Header name and it's value will be written to internal buffer.
 * If there is no available space in the buffer then
 * buffer will be sent to the underlying socket first.
 *
 * It is illegal to call this operation after body or flush.
 *
 * @param[in] conn Connection to send response header to.
 * @param[in] name Header name.
 * @param[in] value Header value.
 * @return Zero on success.
 *
 * @see http_conn_send_response_status()
 * @see http_conn_send_response_body()
 * @see http_conn_flush_response()
 * @relates HTTP_Conn
 */
int http_conn_send_response_header(struct HTTP_Conn *conn,
                                   const char *name,
                                   const char *value);


/**
 * @brief Send custom HTTP response body.
 *
 * Response body will be written to internal buffer.
 * If there is no available space in the buffer then
 * buffer will be sent to the underlying socket first.
 *
 * It is illegal to call this operation after flush.

 * @param[in] conn Connection to send response body to.
 * @param[in] buf Response body.
 * @param[in] len Response body length in bytes.
 * @return Zero on success.
 *
 * @see http_conn_send_response_status()
 * @see http_conn_send_response_header()
 * @see http_conn_flush_response()
 * @relates HTTP_Conn
 */
int http_conn_send_response_body(struct HTTP_Conn *conn,
                                 const void *buf, int len);

/**
 * @brief Finish response sending.
 *
 * This function sends all remainging data from
 * internal buffer to the underlying socket.
 *
 * @param[in] conn Connection to finish response.
 * @return Zero on success.
 *
 * @see http_conn_send_response_status()
 * @see http_conn_send_response_header()
 * @see http_conn_send_response_body()
 * @relates HTTP_Conn
 */
int http_conn_flush_response(struct HTTP_Conn *conn);

#endif // HTTP connection - server related

#endif // HTTP connection


// HTTP client
#if defined(HTTP_CLIENT)

/**
 * @brief HTTP client.
 */
struct HTTP_Client
{
    /**
     * @brief SSL context.
     *
     * Contains certificate, private key, ciphers, etc.
     */
    WOLFSSL_CTX *ctx;

#if HTTP_CLIENT_CONN_CACHE_SIZE > 0

    /**
     * @brief Connection cache entry.
     * @see connecion_cache
     */
    struct HTTP_ClientConnCacheEntry
    {
        /**
         * @brief Cached connection.
         */
        struct HTTP_Conn *conn;

        // TODO: lifetime? check alive?
    } conn_cache[HTTP_CLIENT_CONN_CACHE_SIZE]; /**< @brief Connection cache. */

    // TODO: connection cache mutex
#endif // HTTP_CLIENT_CONN_CACHE_SIZE

#if HTTP_RESOLVE_CACHE_SIZE > 0
/**
 * @brief SHA-1 is used as host digest.
 * @see resolve_cache
 */
# define HTTP_HOST_DIGEST_SIZE (20)

    /**
     * @brief Resolve cache entry.
     *
     * SHA-1 digest is used to identify target host.
     * It has fixed size for all hosts.
     *
     * @see resolve_cache
     */
    struct HTTP_ResolveCacheEntry
    {
        /**
         * @brief SHA-1 digest of target host.
         */
        uint8_t host_dig[HTTP_HOST_DIGEST_SIZE];

        /**
         * @brief IPv4 address resolved.
         *
         * Zero if item is not resolved.
         */
        uint32_t ipv4;

        /*
         * @brief Resolving time, seconds.
         *
         * This time can be used to check item lifetime.
         */
        // uint32_t resolved_time;

        /**
         * @brief Number of times this item used.
         */
        uint32_t use_count;

    } resolve_cache[HTTP_RESOLVE_CACHE_SIZE]; /**< @brief Resolve cache. */
#endif // HTTP_RESOLVE_CACHE_SIZE
};


/**
 * @brief Client's callback prototype.
 *
 * Example:
 *
 * ```
 * int client_cb(int err, struct HTTP_Conn *conn, void*)
 * {
 *     if (err != 0)
 *         return err; // not connected
 *
 *     // send request
 *     // http_conn_send_request_header(conn, "User-Agent", "tinyhttp");
 *     // http_conn_send_request_body(conn, "Hello", 5);
 *     http_conn_flush_request(conn); // actually send request
 *
 *     // receive response
 *     http_conn_recv_response_status(conn);
 *     // TODO: check http_conn_get_response_status(conn) here
 *     // http_conn_ignore_response_headers(conn);
 *     // http_conn_ignore_response_body(conn);
 *
 *     return 0; // OK
 * }
 * ```
 *
 * @see http_client_do()
 * @relates HTTP_Client
 */
typedef int (*HTTP_ClientCallback)(int err, struct HTTP_Conn *conn, void *user_data);


/**
 * @brief Create new HTTP client.
 *
 * @param[in] proto Decided SSL protocol version.
 * @param[out] client New HTTP client.
 * @return Zero on success.
 *
 * @see http_client_free()
 * @relates HTTP_Client
 */
int http_client_new(enum SSL_Proto proto,
                    struct HTTP_Client **client);


/**
 * @brief Release existing HTTP client.
 *
 * @param[in] client HTTP client to release.
 *
 * @see http_client_new()
 * @relates HTTP_Client
 */
void http_client_free(struct HTTP_Client *client);


/**
 * @brief Load trusted root certificate (from file).
 *
 * Certificate is loaded from file on filesystem.
 * Files should be in PEM format!
 *
 * @param[in] client HTTP client.
 * @param[in] cert_file Certificate filepath to load from.
 * @return Zero on success.
 *
 * @see http_client_load_verify_cert_asn1()
 * @relates HTTP_Client
 */
int http_client_load_verify_cert_file(struct HTTP_Client *client,
                                      const char *cert_file);


/**
 * @brief Load trusted root certificate (ASN1 format).
 *
 * Certificate should be in ASN1 format!
 *
 * To convert PEM file to ASN1 just use
 * `openssl x509 -inform pem -in cert.pem -outform DER -out cert.der` command.
 * To embed it in C use `xxd --include cert.der`
 *
 * @param[in] client HTTP client.
 * @param[in] cert Input buffer containing the certificate to be loaded.
 * @param[in] cert_len Size of the certificate input buffer.
 * @return Zero on success.
 *
 * @see http_client_load_verify_cert_file()
 * @relates HTTP_Client
 */
int http_client_load_verify_cert_asn1(struct HTTP_Client *client,
                                      const void *cert, int cert_len);


/**
 * @brief Set list of ciphers to use.
 *
 * The ciphers in the colon-delimited list and should be sorted
 * in order of preference from highest to lowest. For example:
 * `"DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256"`.
 *
 * See corresponding WolfSSL documentation for the
 * list of ciphers supported.
 *
 * @param[in] client HTTP client.
 * @param[in] cipher_list Colon-delimited list of ciphers to use.
 * @return Zero on success.
 *
 * @relates HTTP_Client
 */
int http_client_set_cipher_list(struct HTTP_Client *client,
                                const char *cipher_list);


/**
 * @brief Do custom HTTP request.
 *
 * Most important thing here is callback function.
 * This callback should modify and send request and receive response.
 *
 * @param[in] client HTTP client to handle request.
 * @param[in] method HTTP method.
 * @param[in] url URL to access.
 * @param[in] callback Callback function to handle this request.
 * @param[in] user_data Custom user data.
 * @param[in] flags Combination of connection-related flags.
 * @return Non-zero on success.
 *
 * @see HTTP_ConnFlags
 * @relates HTTP_Client
 */
int http_client_do(struct HTTP_Client *client,
                   enum HTTP_Method method,
                   const char *url,
                   HTTP_ClientCallback callback,
                   void *user_data,
                   uint32_t flags);


/**
 * @brief Do `GET` HTTP request.
 * @param[in] client HTTP client to handle request.
 * @param[in] url URL to access.
 * @param[in] callback Callback function to handle this request.
 * @param[in] user_data Custom user data.
 * @param[in] flags Combination of connection-related flags.
 * @return Non-zero on success.
 *
 * @see http_client_do()
 * @see HTTP_ConnFlags
 * @relates HTTP_Client
 */
static inline int http_client_get(struct HTTP_Client *client,
                                  const char *url,
                                  HTTP_ClientCallback callback,
                                  void *user_data,
                                  uint32_t flags)
{
    return http_client_do(client, HTTP_GET, url,
                          callback, user_data, flags);
}


/**
 * @brief Do `PUT` HTTP request.
 * @param[in] client HTTP client to handle request.
 * @param[in] url URL to access.
 * @param[in] callback Callback function to handle this request.
 * @param[in] user_data Custom user data.
 * @param[in] flags Combination of connection-related flags.
 * @return Non-zero on success.
 *
 * @see http_client_do()
 * @see HTTP_ConnFlags
 * @relates HTTP_Client
 */
static inline int http_client_put(struct HTTP_Client *client,
                                  const char *url,
                                  HTTP_ClientCallback callback,
                                  void *user_data,
                                  uint32_t flags)
{
    return http_client_do(client, HTTP_PUT, url,
                          callback, user_data, flags);
}


/**
 * @brief Do `POST` HTTP request.
 * @param[in] client HTTP client to handle request.
 * @param[in] url URL to access.
 * @param[in] callback Callback function to handle this request.
 * @param[in] user_data Custom user data.
 * @param[in] flags Combination of connection-related flags.
 * @return Non-zero on success.
 *
 * @see http_client_do()
 * @see HTTP_ConnFlags
 * @relates HTTP_Client
 */
static inline int http_client_post(struct HTTP_Client *client,
                                   const char *url,
                                   HTTP_ClientCallback callback,
                                   void *user_data,
                                   uint32_t flags)
{
    return http_client_do(client, HTTP_POST, url,
                          callback, user_data, flags);
}


/**
 * @brief Do `DELETE` HTTP request.
 * @param[in] client HTTP client to handle request.
 * @param[in] url URL to access.
 * @param[in] callback Callback function to handle this request.
 * @param[in] user_data Custom user data.
 * @param[in] flags Combination of connection-related flags.
 * @return Non-zero on success.
 *
 * @see http_client_do()
 * @see HTTP_ConnFlags
 * @relates HTTP_Client
 */
static inline int http_client_delete(struct HTTP_Client *client,
                                     const char *url,
                                     HTTP_ClientCallback callback,
                                     void *user_data,
                                     uint32_t flags)
{
    return http_client_do(client, HTTP_DELETE, url,
                          callback, user_data, flags);
}

#endif // HTTP_CLIENT


// HTTP server
#if defined(HTTP_SERVER)

/**
 * @brief Server's callback prototype.
 *
 * Example:
 *
 * ```
 * int server_cb(int err, struct HTTP_Conn *conn, void*)
 * {
 *     if (err != 0)
 *         return err; // not connected
 *
 *     // receive request
 *     // http_conn_ignore_request_headers(conn);
 *     // http_conn_ignore_request_body(conn);
 *
 *     // send response
 *     http_conn_set_response_status(conn, HTTP_STATUS_NOT_FOUND);
 *     http_conn_send_response_status(conn);
 *     // http_conn_send_response_header(conn, "Connection", "close");
 *     // http_conn_send_response_body(conn, "Hello", 5);
 *
 *     return 0; // OK
 * }
 * ```
 *
 * @see http_server_main_loop()
 */
typedef int (*HTTP_ServerCallback)(int err, struct HTTP_Conn *conn, void *user_data);


/**
 * @brief HTTP server endpoint.
 *
 * Contains one REST endpoint related data.
 */
struct HTTP_Endpoint
{
    /**
     * @brief Allowed methods.
     *
     * For example "GET|POST".
     * If `NULL` all methods are allowed.
     */
    const char *methods;

    /**
     * @brief URI path to handle.
     *
     * For example "/version" or "/user/info*".
     * Wildcards `*` and `?` can be used.
     */
    const char *uri_path;

    /**
     * @brief Callback function.
     *
     * Processing function. Should read request body and write appropriate response.
     */
    HTTP_ServerCallback callback;

    /**
     * @brief Custom user data.
     *
     * Will be passed in corresponding field of connection.
     */
    void *user_data;
};


/**
 * @brief HTTP server.
 *
 * Contains main "listen" socket and manages connections.
 */
struct HTTP_Server
{
    /**
     * @brief Array of REST endpoints.
     *
     * Contains URI path and corresponding callback for each entry.
     */
    const struct HTTP_Endpoint *endpoints;

    /**
     * @brief Number of REST endpoints.
     */
    int n_endpoints;

    /**
     * @brief Default callback for unknown URI.
     */
    int (*not_found_cb)(int, struct HTTP_Conn*);


    /**
     * @brief Socket file descriptor to listen secure connections on.
     */
    int fds;

    /**
     * @brief Socket file descriptor to listen non-secure connections on.
     */
    int fd;

    /**
     * @brief SSL context.
     *
     * Contains certificate, private key, ciphers, etc.
     */
    WOLFSSL_CTX *ctx;


    /**
     * @brief Stopped flag.
     */
    volatile int stopped;
};


/**
 * @brief Create new HTTP server.
 * @param[in] proto Decided SSL protocol version.
 * @param[out] server New HTTP server.
 * @return Zero on success.
 *
 * @see http_server_free()
 * @relates HTTP_Server
 */
int http_server_new(enum SSL_Proto proto,
                    struct HTTP_Server **server);


/**
 * @brief Release existing HTTP server.
 * @param[in] server HTTP server to release.
 *
 * @see http_server_new()
 * @relates HTTP_Server
 */
void http_server_free(struct HTTP_Server *server);


/**
 * @brief Set HTTP server endpoints.
 * @param[in] server HTTP server.
 * @param[in] endpoints Array of custom REST endpoints.
 * @param[in] num_of_endpoints Number of endpoints.
 *
 * @relates HTTP_Server
 */
void http_server_set_endpoints(struct HTTP_Server *server,
                               const struct HTTP_Endpoint *endpoints,
                               int num_of_endpoints);


/**
 * @brief Set SSL certificate and/or private key (from files).
 *
 * Certificate and private key are loaded from file on filesystem.
 * Files should be in PEM format!
 *
 * @param[in] server HTTP server.
 * @param[in] cert_file Certificate filepath to load from.
 * @param[in] key_file Private key filepath to load from.
 * @return Zero on success.
 *
 * @relates HTTP_Server
 */
int http_server_use_cert_file(struct HTTP_Server *server,
                              const char *cert_file,
                              const char *key_file);


/**
 * @brief Set SSL certificate and/or private key.
 *
 * Certificate and private key should be in ASN1 format!
 *
 * @param[in] server HTTP server.
 * @param[in] cert Input buffer containing the certificate to be loaded.
 * @param[in] cert_len Size of the certificate input buffer.
 * @param[in] key Input buffer containing the private key to be loaded.
 * @param[in] key_len Size of the private key input buffer.
 * @return Zero on success.
 *
 * @relates HTTP_Server
 */
int http_server_use_cert_asn1(struct HTTP_Server *server,
                              const void *cert, int cert_len,
                              const void *key, int key_len);


/**
 * @brief Set list of ciphers to use.
 *
 * The ciphers in the colon-delimited list and should be sorted
 * in order of preference from highest to lowest. For example:
 * `"DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256"`.
 *
 * See corresponding WolfSSL documentation for the
 * list of ciphers supported.
 *
 * @param[in] server HTTP server.
 * @param[in] cipher_list Colon-delimited list of ciphers to use.
 * @return Zero on success.
 *
 * @relates HTTP_Server
 */
int http_server_set_cipher_list(struct HTTP_Server *server,
                                const char *cipher_list);


/**
 * @brief Start HTTPS server.
 *
 * Starts listening for secure connections on the specified port.
 *
 * @param[in] server HTTP server to start.
 * @param[in] port Port number to listen secure connections on.
 * @param[in] backlog Maximum length to which the queue
 *                    of pending connections may grow.
 * @return Zero on success.
 *
 * @relates HTTP_Server
 */
int http_server_start_secure(struct HTTP_Server *server,
                             int port, int backlog);


/**
 * @brief Start HTTP server.
 *
 * Starts listening for non-secure connections on the specified port.
 *
 * @param[in] server HTTP server to start.
 * @param[in] port Port number to listen non-secure connections on.
 * @param[in] backlog Maximum length to which the queue
 *                    of pending connections may grow.
 * @return Zero on success.
 *
 * @relates HTTP_Server
 */
int http_server_start(struct HTTP_Server *server,
                      int port, int backlog);


/**
 * @brief Main HTTP server loop.
 *
 * Accepts incomming connections.
 *
 * @param server HTTP server.
 * @return Zero on success.
 *
 * @relates HTTP_Server
 */
int http_server_main_loop(struct HTTP_Server *server);


/**
 * @brief Stop HTTP server.
 *
 * Terminates all active connections and stops accept thread.
 *
 * @param server HTTP server to stop.
 * @return Zero on success.
 *
 * @relates HTTP_Server
 */
int http_server_stop(struct HTTP_Server *server);

#endif // HTTP_SERVER


/**
 * @brief Parse URL into components.
 * @param[in] url URL to parse.
 * @param[out] proto Protocol position.
 *                   If no protocol is present then "https" is used as fallback.
 *                   Note, this string is not NULL-terminated!
 * @param[out] proto_len Protocol length.
 * @param[out] host Target host position.
 *                  Note, this string is not NULL-terminated!
 * @param[out] host_len Target host length.
 * @param[out] port Port number.
 *                  If no port number is present it is detected based on protocol.
 *                  If protocol is unknown then `port` is not changed.
 * @param[out] path URI path position.
 *                  Note, this string is not NULL-terminated!
 * @param[out] path_len URI path length.
 * @return Zero on success.
 */
int http_parse_url(const char *url,
                   const char **proto, int *proto_len,
                   const char **host, int *host_len, int *port,
                   const char **path, int *path_len);


/**
 * @brief Parse query parameter.
 * @param[in,out] query Begin of query on input.
 *                      Next position on output.
 * @param[out] name Parameter name.
 *                  Note, this string is not NULL-terminated!
 * @param[out] name_len Parameter name length in bytes.
 * @param[out] value Parameter value if present.
 *                  Note, this string is not NULL-terminated!
 * @param value_len Parameter value length in bytes.
 * @return Zero on success.
 *
 * @see http_get_query_param()
 */
int http_parse_query(const char **query,
                     const char **name, int *name_len,
                     const char **value, int *value_len);


/**
 * @brief Get query parameter by name.
 *
 * If there are a few parameters with the same name
 * only the first occurrence is returned.
 *
 * @param[in] query Query string.
 * @param[in] name Query parameter name to get.
 * @param[out] value Parameter value.
 * @param[out] value_len Parameter value length in bytes.
 * @return Zero on success.
 *
 * @see http_parse_query()
 */
int http_get_query_param(const char *query,
                         const char *name,
                         const char **value,
                         int *value_len);


/**
 * @brief Match the URI.
 *
 * - `?` matches one character
 * - `*` matches zero or more characters
 *
 * @param[in] pattern Pattern to match.
 * @param[in] uri URI to match.
 * @return Non-zero if matched.
 */
int http_match_uri(const char *pattern, const char *uri);


/**
 * @brief Find the "\r\n" occurrence.
 * @param[in] buf Begin of data buffer.
 * @param[in] len Total number of bytes available.
 * @return Position of "\r\n" or `NULL` if not found.
 */
const void* http_find_crlf(const void *buf, int len);

#if defined(__cplusplus)
} // extern "C"
#endif // __cplusplus

#endif // __HTTP_H__


/**
 * @page http_page HTTP common
 *
 * There are a few data structures and functions related to
 * both @ref client_page and @ref server_page.
 *
 * - SSL_Proto enum is used to define all possible SSL protocols.
 * - HTTP_Method enum is used to define all possible HTTP methods.
 * - HTTP_Proto enum is used to define all supported HTTP protocols.
 * - HTTP_Status enum is used to define some popular HTTP status codes.
 * - HTTP_Error enum contains all possible error codes.
 * - HTTP_ConnFlags enum contains bit field options related to connection.
 *
 * The following enums are used as various headers:
 * - HTTP_HeaderConnection enum for "Connection" header
 */


/**
 * @page client_page HTTP client
 *
 * HTTP_Client sends HTTP requests and parses HTTP responses.
 * @tableofcontents
 *
 * @section resolve_cache Resolve cache
 *
 * TBD
 *
 * @section connection_cache Connection cache
 *
 * TBD
 */


/**
 * @page server_page HTTP server
 *
 * TBD
 */



/* Cheat-Sheet
 *
 * to test server:
 * `curl --cacert server-cert.pem -H "Text: Hello" -s "https://www.wolfssl.com:8080/version"`
 *
 * to convert certificates from CRT (actually PEM) to binary DER format:
 * `for name in *.crt; do openssl x509 -inform PEM -outform DER -in $name -out $name.der; done`
 *
 * to convert all certificates to C "include" file:
 * `echo "# all certificates" > cert.c; for name in *.der; do xxd -i $name >> cert.c; done`
 *
 * # apply all certificates:
 * echo "void load_all(WOLFSSL_CTX *ctx) {" >> cert.c;
 * for name in `cat cert.h | sed -n "s|unsigned char \(.*\)\[\] = {|\1|p"`; do echo "  wolfSSL_CTX_load_verify_buffer(ctx, ${name}, ${name}_len, WOLFSSL_FILETYPE_ASN1);" >> cert.c; done
 * echo "}" >> cert.c
 */

/* TODO
 *
 * - short tutorial with examples!
 * + time performance metrics for client/server requests
 * - client: dedicated thread per each request
 * - client: limit the maximum number of connections
 * - client: limit the total request execution time
 * - client: support for chunked transfer
 * - client: support basic authentication (strip username/password from URL)
 * + server: support both http and https at the same time
 * - server: dedicated thread per each request
 * - server: dedicated thread for listen+accept
 * - server: limit the maximum number of connections
 * - server: limit the total request execution time
 *
 * wrappers for (corresponding flags to http_client_do()):
 * - wolfSSL_CTX_UseSNI()
 * - wolfSSL_UseSNI()
 * - wolfSSL_check_domain_name()
 */
