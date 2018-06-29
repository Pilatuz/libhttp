#include "http.h"

// logging tweaks
#undef  LOG_MODULE
#define LOG_MODULE "server"
#include "misc.h"

#include <string.h>
#include <stdio.h>

#if !defined(HTTP_SERVER)
# error No support of HTTP server enabled
#endif // HTTP_SERVER

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
 * @brief Application entry point.
 * @return Zero on success.
 */
int main(void)
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
