/* SPDX-FileCopyrightText: 2026 Anthony Green
 * SPDX-License-Identifier: Apache-2.0
 * Test-only guest probe: one HTTP connection from a fixed source port, then RST or FIN.
 * Build statically on the development host; the guest needs no compiler/libc.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void fail(const char *message) {
    perror(message);
    exit(1);
}

static void json_string(const char *text) {
    putchar('"');
    for (const unsigned char *c = (const unsigned char *)text; *c; ++c) {
        if (*c == '"' || *c == '\\') printf("\\%c", *c);
        else if (*c < 32) printf("\\u%04x", *c);
        else putchar(*c);
    }
    putchar('"');
}

int main(int argc, char **argv) {
    if (argc != 3 && (argc != 4 || strcmp(argv[3], "fin"))) {
        fprintf(stderr, "usage: service-tcp-client SERVICE_IPV4 LOCAL_PORT [fin]\n");
        return 2;
    }
    char *end = NULL;
    long port = strtol(argv[2], &end, 10);
    if (!end || *end || port < 1024 || port > 65535) return 2;
    alarm(12);
    int fd = socket(AF_INET, SOCK_STREAM, 0), yes = 1;
    if (fd < 0) fail("socket");
    struct linger reset = {.l_onoff = 1, .l_linger = 0};
    struct timeval timeout = {.tv_sec = 10};
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) ||
        (argc == 3 && setsockopt(fd, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset))) ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) fail("setsockopt");
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(80)};
    if (inet_pton(AF_INET, argv[1], &peer.sin_addr) != 1) return 2;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local))) fail("bind");
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) fail("connect");
    static const char request[] = "GET /hostname HTTP/1.1\r\nHost: gr8s-service-test\r\nConnection: keep-alive\r\n\r\n";
    size_t sent = 0;
    while (sent < sizeof(request) - 1) {
        ssize_t count = send(fd, request + sent, sizeof(request) - 1 - sent, 0);
        if (count < 0) { if (errno == EINTR) continue; fail("send"); }
        if (!count) return 1;
        sent += (size_t)count;
    }
    char response[8192], *body = NULL;
    size_t used = 0, wanted = 0;
    while (used < sizeof(response) - 1) {
        ssize_t count = recv(fd, response + used, sizeof(response) - 1 - used, 0);
        if (count < 0) { if (errno == EINTR) continue; fail("recv"); }
        if (!count) { fprintf(stderr, "incomplete HTTP response\n"); return 1; }
        used += (size_t)count;
        response[used] = 0;
        if (!body) {
            char *header_end = strstr(response, "\r\n\r\n");
            if (!header_end) continue;
            if (strncmp(response, "HTTP/1.1 200 ", 13)) { fprintf(stderr, "unexpected HTTP status\n"); return 1; }
            body = header_end + 4;
            int length_seen = 0;
            for (char *line = response; line < header_end;) {
                if (!strncasecmp(line, "Content-Length:", 15)) {
                    wanted = strtoul(line + 15, NULL, 10);
                    length_seen = 1;
                }
                char *next = strstr(line, "\r\n");
                if (!next) break;
                line = next + 2;
            }
            if (!length_seen || wanted > sizeof(response) - (size_t)(body - response) - 1) {
                fprintf(stderr, "missing/oversized Content-Length\n"); return 1;
            }
        }
        if (used - (size_t)(body - response) >= wanted) break;
    }
    if (!body || used - (size_t)(body - response) < wanted) return 1;
    body[wanted] = 0;
    socklen_t size = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &size)) fail("getsockname");
    size = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &size)) fail("getpeername");
    char local_ip[INET_ADDRSTRLEN], peer_ip[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &local.sin_addr, local_ip, sizeof(local_ip)) ||
        !inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip))) fail("inet_ntop");
    printf("{\"localIP\":"); json_string(local_ip);
    printf(",\"localPort\":%u,\"peerIP\":", ntohs(local.sin_port)); json_string(peer_ip);
    printf(",\"peerPort\":%u,\"body\":", ntohs(peer.sin_port)); json_string(body);
    puts("}");
    if (argc == 4) {
        if (shutdown(fd, SHUT_WR)) fail("shutdown");
        char tail[256];
        for (;;) {
            ssize_t count = recv(fd, tail, sizeof(tail), 0);
            if (count < 0) { if (errno == EINTR) continue; fail("close recv"); }
            if (!count) break;
        }
    }
    if (close(fd)) fail("close");
    return 0;
}
