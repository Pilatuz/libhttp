#include "http.h"

// logging tweaks
#undef  LOG_MODULE
#define LOG_MODULE "main"
#include "misc.h"

#include <alloca.h>
#include <string.h>
#include <stdio.h>

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
    const int all = 1;

    if (all)
    {
        test_parse_query("hello=world&test=1&foo&=&foo=&=bar x#frag", "hello", "world");
        test_parse_query("hello=world&test=1&foo&=&foo=&=bar x#frag", "test", "1");
        test_parse_query("hello=world&test=1&foo&=&foo=&=bar x#frag", "bad", 0);
    }

    if (all)
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

    if (all)
    {
        test_match_uri("/version", "/version", 1);
        test_match_uri("/version/*", "/version/1", 1);
        test_match_uri("/version/*", "/version/2#hello", 1);
        test_match_uri("/version/*", "/version/2?hello=1", 1);
        test_match_uri("/user/*/add", "/user/John/add", 1);
        test_match_uri("/user/*/add", "/user/Mery/del", 0);
        test_match_uri("/user/*", "/user/Mery/del?hello=no", 1);
    }

    if (all)
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
