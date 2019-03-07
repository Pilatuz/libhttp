#include "http.h"

// logging tweaks
#undef  LOG_MODULE
#define LOG_MODULE "client"
#include "misc.h"

#include <string.h>
#include <stdio.h>

#if !defined(HTTP_CLIENT)
# error No support of HTTP client enabled
#endif // HTTP_CLIENT

/**
 * @brief Print whole server response to the log.
 *
 * This is test client callback function that prints the whole response.
 */
static int test_print_response(int err, struct HTTP_Conn *conn, void *user_data)
{
    (void)user_data;
    if (HTTP_ERR_SUCCESS != err)
    {
        ERROR("failed to connect: %d\n", err);
        return err;
    }
    INFO("connected, preparing request...\n");

    // http_conn_set_request_proto(conn, HTTP_PROTO_1_0);
    // http_conn_add_request_uri(conn, "?hello=yes");
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
    if (!!http_conn_recv_response_status(conn))
    {
        WARN("failed to receive status\n");
        return -1;
    }
    if (http_conn_get_response_status(conn) != HTTP_STATUS_OK)
    {
        WARN("unexpected status: %d\n", http_conn_get_response_status(conn));
        http_conn_ignore_response_body(conn);
        return -1; // failed
    }

    // ignore rest of headers
    if (!!http_conn_ignore_response_headers(conn))
    {
        WARN("failed to recv headers\n");
        return -1;
    }

    INFO("reading response body...\n");
    uint8_t tmp_buf[4*1024];
    int rem;
    while ((rem = http_conn_response_content_can_recv(conn)) > 0)
    {
        if (rem > (int)sizeof(tmp_buf))
            rem = sizeof(tmp_buf);

        const int err = http_conn_recv_response_body(conn, tmp_buf, &rem);
        if (HTTP_ERR_SUCCESS != err)
            return err; // failed
        if (!rem)
            break;

        INFO("*** %d bytes read ***\n", rem);
        fwrite(tmp_buf, 1, rem, stdout); // print to stdout
    }

    INFO("*** request done\n");
    return 0; // OK
}


/**
 * @brief Application entry point.
 * @return Zero on success.
 */
int main(void)
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
    wolfSSL_CTX_UseSNI(client->ctx, 0, "badssl.com", 9);

    wolfSSL_CTX_load_verify_locations(client->ctx, NULL, "/etc/ssl/certs/");
    //http_client_load_verify_cert_file(client, "/home/dataart/test/http/server-cert.pem"); // www.wolfssl.com
    //http_client_load_verify_cert_file(client, "/etc/ssl/certs/DST_Root_CA_X3.pem"); // www.howsmyssl.com
    //http_client_load_verify_cert_file(client, "/etc/ssl/certs/USERTrust_RSA_Certification_Authority.pem"); // reqres.in + jsonplaceholder.typicode.com
    //http_client_load_verify_cert_file(client, "/etc/ssl/certs/Baltimore_CyberTrust_Root.pem"); // fakerestapi.azurewebsites.net

    http_client_get(client, "https://badssl.com/",
                    //"https://www.howsmyssl.com/a/check",
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
