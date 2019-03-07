#include "http.h"

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>

// logging tweaks
#undef  LOG_MODULE
#define LOG_MODULE "main"
#include "misc.h"

#include <alloca.h>
#include <string.h>
#include <stdio.h>

// HTTP server test
#if defined(HTTP_SERVER)

/**
 * @brief The `/version` handler.
 */
static int test_version(int err, struct HTTP_Conn *conn, void *user_data)
{
    (void)err; // fake use
    (void)user_data;

    // write reply into socket
    const char reply[] = "{\"version\":\"0.1\"}\n";
    int len = sizeof(reply)-1;

    http_conn_set_response_status(conn, HTTP_STATUS_OK); // OK
    http_conn_send_response_header(conn, "Connection", "close");
    http_conn_send_response_body(conn, reply, len);
    http_conn_flush_response(conn);

    INFO("writing %d bytes /version reply: %s", len, reply);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief The `/shutdown` handler.
 */
static int test_shutdown(int err, struct HTTP_Conn *conn, void *user_data)
{
    (void)err;

    // write reply into socket
    const char reply[] = "{\"status\":\"done\"}\n";
    int len = sizeof(reply)-1;

    struct HTTP_Server **server = (struct HTTP_Server**)user_data;
    if (server && *server)
    {
        INFO("SHUTDOWN command received, stop the server!\n");
        http_server_stop(*server);
    }

    http_conn_set_response_status(conn, HTTP_STATUS_OK); // OK
    http_conn_send_response_header(conn, "Connection", "close");
    http_conn_send_response_body(conn, reply, len);
    http_conn_flush_response(conn);

    INFO("writing %d bytes /shutdown reply: %s", len, reply);
    return HTTP_ERR_SUCCESS; // OK
}


/**
 * @brief Server example.
 * @return Zero on success.
 */
static int test_server(void)
{
    struct HTTP_Server *server = 0;
    const char *cert_file = "server-cert.pem";
    const char *key_file = "server-key.pem";
    const int secure_port = 8443;
    const int port = 8080;
    const int backlog = 8;
    int res = 0; // OK by default

    // HTTP test endpoints
    const struct HTTP_Endpoint endpoints[] =
    {
        {"GET", "/version",     test_version, &server},
        {"*",   "/shutdown",    test_shutdown, &server},
    };

    // initialize WolfSSL library
    const int err = wolfSSL_Init();
    if (WOLFSSL_SUCCESS != err)
    {
        ERROR("failed to initialize WolfSSL library\n");
        goto failed; // failed
    }
    wolfSSL_Debugging_OFF();
    // wolfSSL_SetLoggingCb(wolf_log_cb);
    INFO("wolfSSL version: %s\n",
         wolfSSL_lib_version());

    // create HTTP server
    if (!!http_server_new(SSL_PROTO_TLSv1_2, &server))
    {
        ERROR("failed to create HTTP server\n");
        goto failed; // failed
    }

    // initialize server SSL context
    if (!!http_server_use_cert_file(server, cert_file, key_file))
    {
        ERROR("failed to set SSL certificate and private key\n");
        goto failed; // failed
    }

    // TODO: http_server_set_cipher_list(server, "???");
    http_server_set_endpoints(server, endpoints,
                              sizeof(endpoints)/sizeof(endpoints[0]));

    // initialize server secure socket
    if (!!http_server_start_secure(server, secure_port, backlog))
    {
        ERROR("failed to listen server secure socket\n");
        goto failed; // failed
    }

    // initialize server socket
    if (!!http_server_start(server, port, backlog))
    {
        ERROR("failed to listen server socket\n");
        goto failed; // failed
    }

    // main "accept" loop (TODO: move to dedicated thread)
    if (!!http_server_main_loop(server))
    {
        ERROR("failed to serve\n");
        goto failed; // failed
    }

    if (0)
    {
        // tricky way to set exit code to -1
        // in normal scenario this code is always ignored
failed:
        res = -1;
    }

    DEBUG("cleaning up...\n");

    // stop and release HTTP server
    http_server_stop(server);
    http_server_free(server);

    wolfSSL_Cleanup();

    DEBUG("http server test completed (exit code: %d)\n", res);
    return res;
}

#endif // HTTP_SERVER

// HTTP client test
#if defined(HTTP_CLIENT)

/**
 * @brief Print whole server response to the log.
 *
 * This is test client callback function that prints the whole response.
 */
static int test_print_response(int err, struct HTTP_Conn *conn, void *user_data)
{
    (void)user_data;
    if (err != 0)
    {
        ERROR("failed to connect: %d\n", err);
        return err;
    }
    INFO("connected, preparing request...\n");

    // http_conn_set_request_proto(conn, HTTP_PROTO_1_0);
    http_conn_add_request_uri(conn, "?hello=yes");
    http_conn_send_request_header(conn, "Agent", "tinyhttp/0.1");
    http_conn_send_request_header(conn, "Accept", "*/*");
    // http_conn_set_request_uri(conn, "/index.html", -1);
    if (!!http_conn_flush_request(conn))
    {
        WARN("failed to send request\n");
        return -1;
    }
    INFO("request sent, waiting for response...\n");

    // check response status
    if (!!http_conn_recv_response_status(conn)
       || http_conn_get_response_status(conn) != HTTP_STATUS_OK)
    {
        WARN("failed to receive status or bad status\n");
        return -1;
    }

    // ignore rest of headers
    if (!!http_conn_ignore_response_headers(conn))
    {
        WARN("failed to recv headers\n");
        return -1;
    }

    int64_t rem = conn->response.headers.content_length;
    if (rem > 0)
    {
        INFO("reading %lld bytes of response body...\n",
             (long long int)rem);
        uint8_t tmp_buf[HTTP_CONN_BUF_SIZE];
        while (rem > 0)
        {
            int n = (rem <= (int64_t)sizeof(tmp_buf)) ? (int)rem : (int)sizeof(tmp_buf);
            const int err = http_conn_recv_response_body(conn, tmp_buf, &n);
            if (HTTP_ERR_SUCCESS != err)
                return err; // failed
            if (!n)
                break;

            INFO("*** %d bytes read ***\n", n);
            rem -= n;

            fwrite(tmp_buf, 1, n, stdout); // print to stdout
        }
    }

    INFO("*** request done\n");
    return 0; // OK
}


/**
 * @brief Client example.
 * @return Zero on success.
 */
static int test_client(void)
{
    struct HTTP_Client *client = 0;
    int res = 0; // OK by default

    // initialize WolfSSL library
    const int err = wolfSSL_Init();
    if (WOLFSSL_SUCCESS != err)
    {
        ERROR("failed to initialize WolfSSL library\n");
        goto failed; // failed
    }
    wolfSSL_Debugging_OFF();
    INFO("wolfSSL version: %s\n",
         wolfSSL_lib_version());

    // create HTTP client
    if (!!http_client_new(SSL_PROTO_TLSv1_2, &client))
    {
        ERROR("failed to create HTTP client\n");
        goto failed; // failed
    }

    // TODO: initialize client SSL context
    // TODO: http_client_set_cipher_list(client, "???");
    // wolfSSL_CTX_UseSNI(client->ctx, 0, "reqres.in", 9);

    //wolfSSL_CTX_load_verify_locations(client->ctx, NULL, "/etc/ssl/certs/");
    http_client_load_verify_cert_file(client, "/etc/ssl/certs/DST_Root_CA_X3.pem"); // www.howsmyssl.com
    //http_client_load_verify_cert_file(client, "/etc/ssl/certs/USERTrust_RSA_Certification_Authority.pem"); // reqres.in + jsonplaceholder.typicode.com
    //http_client_load_verify_cert_file(client, "/etc/ssl/certs/Baltimore_CyberTrust_Root.pem"); // fakerestapi.azurewebsites.net

    http_client_get(client, "https://www.howsmyssl.com/a/check",
                    //"https://fakerestapi.azurewebsites.net/api/Books/1",
                    //"https://jsonplaceholder.typicode.com/posts/1",
                    //"https://reqres.in/api/user/1",
                    test_print_response, client, 0);

    if (0)
    {
        // tricky way to set exit code to -1
        // in normal scenario this code is always ignored
failed:
        res = -1;
    }

    DEBUG("cleaning up...\n");

    // stop and release HTTP client
    // http_client_stop(client);
    http_client_free(client);

    wolfSSL_Cleanup();

    INFO("http client test completed (exit code: %d)\n", res);
    return res;
}

#endif // HTTP_CLIENT

/**
 * @brief test for `http_parse_url` function.
 */
void test_parse_url(const char *url,
                    const char *expected_proto,
                    const char *expected_host,
                    const char *expected_path,
                    int expected_port)
{
    const char *actual_proto = 0;
    int actual_proto_len = 0;
    const char *actual_host = 0;
    int actual_host_len = 0;
    const char *actual_path = 0;
    int actual_path_len = 0;
    int actual_port = expected_port; // use default

    if (!!http_parse_url(url, &actual_proto, &actual_proto_len,
                         &actual_host, &actual_host_len, &actual_port,
                         &actual_path, &actual_path_len))
        printf("parse(%s) - FAILED\n", url);
    else if ((int)strlen(expected_proto) != actual_proto_len || 0 != strncmp(actual_proto, expected_proto, actual_proto_len))
        printf("parse(%s) proto %s != %.*s FAILED\n", url, expected_proto, actual_proto_len, actual_proto);
    else if ((int)strlen(expected_host) != actual_host_len || 0 != strncmp(actual_host, expected_host, actual_host_len))
        printf("parse(%s) host %s != %.*s FAILED\n", url, expected_host, actual_host_len, actual_host);
    else if ((int)strlen(expected_path) != actual_path_len || 0 != strncmp(actual_path, expected_path, actual_path_len))
        printf("parse(%s) path %s != %.*s FAILED\n", url, expected_path, actual_path_len, actual_path);
    else if (expected_port != actual_port)
        printf("parse(%s) port %d != %d FAILED\n", url, expected_port, actual_port);
    else
        printf("parse(%s) - OK\n", url);
}


/**
 * @brief test for `http_match_uri` function.
 */
void test_match_uri(const char *pattern, const char *uri, int expected)
{
    if (http_match_uri(pattern, uri) != expected)
        printf("match(%s, %s) != %d - FAILED\n", pattern, uri, expected);
    else
        printf("match(%s, %s) - OK\n", pattern, uri);
}


/**
 * @brief test for `http_find_crlf` function.
 */
void test_find_crlf(const char *line, const char *expected)
{
    int len = strlen(line);
    const char *crlf = (const char*)http_find_crlf(line, len);

    // escape non-print symbols
    char *escaped_line = (char*)alloca(2*len);
    for (int i = 0; ; ++i, ++line)
    {
        if (*line == '\r')
        {
            escaped_line[i++] = '\\';
            escaped_line[i] = 'r';
        }
        else if (*line == '\n')
        {
            escaped_line[i++] = '\\';
            escaped_line[i] = 'n';
        }
        else
            escaped_line[i] = *line; // as is

        if (!*line)
            break;
    }

    if (expected)
    {
        if (crlf)
        {
            if (0 == strcmp(expected, crlf))
                printf("find_crlf(%s) - OK\n", escaped_line);
            else
                printf("find_crlf(%s) != %s - FAILED\n", escaped_line, expected);
        }
        else
            printf("find_crlf(%s) NOT FOUND - FAILED\n", escaped_line);
    }
    else
    {
        if (crlf)
            printf("find_crlf(%s) FALSE ALARM - FAILED\n", escaped_line);
        else
            printf("find_crlf(%s) - OK\n", escaped_line);
    }
}

/**
 * @brief Test for `http_parse_query` function.
 */
static void test_parse_query(const char *query, const char *name, const char *expected_value)
{
    while (0)
    {
        const char *name = 0;
        int name_len = 0;
        const char *val = 0;
        int val_len = 0;

        if (!!http_parse_query(&query, &name, &name_len, &val, &val_len))
            break;

        printf("%.*s=%.*s\n",
               name_len, name,
               val_len, val);
    }

    const char *value = 0;
    int value_len = 0;
    if (HTTP_ERR_SUCCESS == http_get_query_param(query, name, &value, &value_len))
    {
        if (expected_value)
        {
            const int expected_len = strlen(expected_value);
            if (expected_len == value_len && 0 == strncmp(expected_value, value, value_len))
            {
                printf("get_query_param(%s, %s) == \"%s\" - OK\n", query, name, expected_value);
            }
            else
            {
                printf("get_query_param(%s, %s) != \"%s\" - FAILED, found \"%.*s\" instead\n",
                       query, name, expected_value, value_len, value);
            }
        }
        else
            printf("get_query_param(%s, %s) - unexpected value found: \"%.*s\"\n",
                   query, name, value_len, value);
    }
    else
    {
        if (!expected_value)
        {
            printf("get_query_param(%s, %s) missing - OK\n", query, name);
        }
        else
        {
            printf("get_query_param(%s, %s) - FAILED, expected \"%s\"\n",
                   query, name, expected_value);
        }
    }
}


/**
 * @brief Application entry point.
 * @return Zero on success.
 */
int main(void)
{
    if (0) return test_server();
    if (0) return test_client();

    if (1) // generate certificate
    {
        // --enable-keygen or WOLFSSL_KEY_GEN

        // int MakeRsaKey(RsaKey* key, int size, long e, RNG* rng);
        // Where size is the length in bits and e is the public exponent,
        // using 65537 is usually a good choice for e.

        RsaKey key;
        WC_RNG rng;
        int    ret;

        wc_InitRng(&rng);
        wc_InitRsaKey(&key, 0);
        ret = wc_MakeRsaKey(&key, 2048, 0x10001, &rng);
        if (ret != 0)
        {
            ERROR("failed to generate RSA key: %d\n", ret);
        }

        // The RsaKey genKey can now be used like any other RsaKey.
        // If you need to export the key, wolfSSL provides both DER and PEM
        // formatting in asn.h. Always convert the key to DER format first,
        // and then if you need PEM use the generic DerToPem() function like this:

        byte der[4096];
        int  derSz = wc_RsaKeyToDer(&key, der, sizeof(der));
        if (derSz < 0)
        {
            ERROR("failed to convert to DER: %d\n", derSz);
            return -1;
        }
        else
        {
            INFO("DER size: %d bytes\n", derSz);
        }

        // The buffer der now holds a DER format of the key.
        // To convert the DER buffer to PEM use the conversion function:

        byte pem[4096];
        int  pemSz = wc_DerToPem(der, derSz, pem, sizeof(pem),
                                 PRIVATEKEY_TYPE);
        if (pemSz < 0)
        {
            ERROR("failed to convert DER to PEM: %d\n", pemSz);
            return -1;
        }
        else
        {
            INFO("PEM size: %d bytes\n", pemSz);
        }

        // The last argument of DerToPem() takes a type parameter,
        // usually either PRIVATEKEY_TYPE or CERT_TYPE.
        // Now the buffer pem holds the PEM format of the key.

        INFO("private key:\n%.*s\n", pemSz, pem);
    }

    if (0)
    {
        test_parse_query("hello=world&test=1&foo&=&foo=&=bar x#frag", "hello", "world");
        test_parse_query("hello=world&test=1&foo&=&foo=&=bar x#frag", "test", "1");
        test_parse_query("hello=world&test=1&foo&=&foo=&=bar x#frag", "bad", 0);
    }

    if (0)
    {
        // port auto-detection
        test_parse_url("https://my.server.com/hello", "https", "my.server.com", "/hello", 443);
        test_parse_url("http://my.server.com/hello", "http", "my.server.com", "/hello", 80);
        test_parse_url("wss://my.server.com/hello", "wss", "my.server.com", "/hello", 443);
        test_parse_url("ws://my.server.com/hello", "ws", "my.server.com", "/hello", 80);
        test_parse_url("ftp://my.server.com/hello", "ftp", "my.server.com", "/hello", 21);
        test_parse_url("telnet://my.server.com/hello", "telnet", "my.server.com", "/hello", 0);

        // custom port
        test_parse_url("https://my.server.com:8080/hello", "https", "my.server.com", "/hello", 8080);
        test_parse_url("http://my.server.com:8080/hello", "http", "my.server.com", "/hello", 8080);
        test_parse_url("https://my.server.com:8080/hello?foo=bar", "https", "my.server.com", "/hello?foo=bar", 8080);
        test_parse_url("https://my.server.com:8080/hello?foo=bar#data", "https", "my.server.com", "/hello?foo=bar#data", 8080);
        test_parse_url("https://my.server.com:8080/hello#data", "https", "my.server.com", "/hello#data", 8080);

        // default values
        test_parse_url("my.server.com:8080/hello", "https", "my.server.com", "/hello", 8080);
        test_parse_url("https://:8080/hello", "https", "", "/hello", 8080);
        test_parse_url("https://my.server.com:/hello", "https", "my.server.com", "/hello", 0);
        test_parse_url("https://my.server.com/", "https", "my.server.com", "/", 443);
        test_parse_url("https://my.server.com", "https", "my.server.com", "", 443);
        test_parse_url("", "https", "", "", 443);
    }

    if (0)
    {
        test_match_uri("/version", "/version", 1);
        test_match_uri("/version/*", "/version/1", 1);
        test_match_uri("/version/*", "/version/2#hello", 1);
        test_match_uri("/version/*", "/version/2?hello=1", 1);
        test_match_uri("/user/*/add", "/user/John/add", 1);
        test_match_uri("/user/*/add", "/user/Mery/del", 0);
        test_match_uri("/user/*", "/user/Mery/del?hello=no", 1);
    }

    if (0)
    {
        test_find_crlf("no", 0);
        test_find_crlf("no\nno", 0);
        test_find_crlf("\nno\nno", 0);
        test_find_crlf("no\nno\rx\nno", 0);
        test_find_crlf("\n\n\r\nyes", "\r\nyes");
        test_find_crlf("no\r\nyes", "\r\nyes");
        test_find_crlf("\r\nyes", "\r\nyes");
        test_find_crlf("no\nno\r\nyes", "\r\nyes");
        test_find_crlf("\nno\r\nyes", "\r\nyes");
    }
}
