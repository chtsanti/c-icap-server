/*
 *  Copyright (C) 2004-2008 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA.
 */

#include "common.h"
#include "c-icap.h"
#include "debug.h"
#include "net_io.h"
#include "port.h"
#include "cfg_param.h"

#include <errno.h>
#include <ws2tcpip.h>

int icap_socket_opts(ci_socket fd, int secs_to_linger);

const char * ci_str_network_error(int err, char *buf, size_t buflen)
{
    DWORD fmtErr = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL,
                                 (DWORD)err,
                                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                 (LPTSTR)&buf,
                                 buflen, NULL);
    return fmtErr ? buf : "<ErrorFormatingError>";
}

const char * ci_str_last_network_error(char *buf, size_t buflen)
{
    DWORD err = WSAGetLastError();
    return ci_str_network_error(err, buf, buflen);
}

const char *ci_sockaddr_t_to_host(ci_sockaddr_t * addr, char *hname,
                                  int maxhostlen)
{
    int ret;
    ret = getnameinfo((const struct sockaddr *)&(addr->sockaddr),
                addr->ci_sin_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in), hname, maxhostlen - 1,
                NULL, 0, 0);
    if (ret == 0)
        return (const char *) hname;

    char buf[512];
    ci_debug_printf(5, "Fatal error while retrieving hostname: %s\n", ci_str_last_network_error(buf, sizeof(buf)));
    snprintf(hname, maxhostlen, "<unknown>");
    return hname;
}

int windows_init()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        return 0;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        WSACleanup();
        return 0;
    }
    return 1;
}

ci_socket icap_init_server(ci_port_t *port)
                           //int port, int *protocol_family, int secs_to_linger)
{
    int er;
    struct sockaddr_in addr;

    if (!windows_init()) {
        ci_debug_printf(1, "Error initialize windows sockets...\n");
    }

    port->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (port->fd == INVALID_SOCKET) {
        er = WSAGetLastError();
        ci_debug_printf(1, "Error opening socket ....%d\n", er);
        return CI_SOCKET_INVALID;
    }

    icap_socket_opts(port->fd, port->secs_to_linger);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port->port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(port->fd, (struct sockaddr *) &addr, sizeof(addr))) {
        ci_debug_printf(1, "Error bind  \n");;
        return CI_SOCKET_INVALID;
    }
    if (listen(port->fd, 512)) {
        ci_debug_printf(1, "Error listen .....\n");
        return CI_SOCKET_INVALID;
    }
    port->protocol_family = AF_INET;
    return port->fd;
}

int icap_socket_opts(ci_socket s, int secs_to_linger)
{
    struct linger li;
    BOOL value;
    /*
         value = TRUE;
         if(setsockopt(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT,
               (const char *)&value, sizeof(value)) == -1){
          ci_debug_printf(1,"setsockopt: unable to set SO_CONDITIONAL_ACCEPT\n");
         }
    */

    value = TRUE;
    if (setsockopt
            (s, SOL_SOCKET, SO_REUSEADDR, (const char *) &value,
             sizeof(value)) == -1) {
        ci_debug_printf(1, "setsockopt: unable to set SO_REUSEADDR\n");
    }

    value = TRUE;
    if (setsockopt
            (s, IPPROTO_TCP, TCP_NODELAY, (const char *) &value,
             sizeof(value)) == -1) {
        ci_debug_printf(1, "setsockopt: unable to set TCP_NODELAY\n");
    }

    li.l_onoff = 1;
    li.l_linger = secs_to_linger;

    if (setsockopt(s, SOL_SOCKET, SO_LINGER,
                   (const char *) &li, sizeof(struct linger)) < 0) {
        ci_debug_printf(1, "setsockopt: unable to set SO_LINGER \n");
    }
    return 1;
}

int ci_connection_set_nonblock(ci_connection_t *conn)
{
    u_long nonblock = 1;
    ioctlsocket(conn->fd, FIONBIO, &nonblock);
    return 1;
}

int ci_wait_ms_for_data(ci_socket fd, int msecs, int what_wait)
{
    fd_set rfds, wfds, efds, *preadfds, *pwritefds, *pexceptfds;
    struct timeval tv;
    int ret = 0;

    if (msecs >= 0) {
        tv.tv_sec = msecs / 1000;
        tv.tv_usec = (msecs % 1000) * 1000;
    }

    preadfds = NULL;
    pwritefds = NULL;
    pexceptfds = NULL;

    if (what_wait & ci_wait_for_read) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        preadfds = &rfds;
    }

    if (what_wait & ci_wait_for_write) {
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        pwritefds = &wfds;
    }

    if (what_wait & ci_wait_for_exceptions) {
        FD_ZERO(&efds);
        FD_SET(fd, &efds);
        pexceptfds = &efds;
    }

    if ((ret =
                select(fd + 1, preadfds, pwritefds, pexceptfds,
                       (msecs >= 0 ? &tv : NULL))) > 0) {
        ret = 0;
        if (preadfds && FD_ISSET(fd, preadfds))
            ret = ci_wait_for_read;
        if (pwritefds && FD_ISSET(fd, pwritefds))
            ret = ret | ci_wait_for_write;
	if (pexceptfds && FD_ISSET(fd, pexceptfds))
            ret = ret | ci_wait_for_exceptions;
        return ret;
    }

    if (ret < 0) {
        DWORD err = WSAGetLastError();
	if (err == WSAEINTR)
	    return ci_wait_should_retry;
	else {
	    char buf[512];
            ci_debug_printf(5, "Fatal error while waiting for new data %d:%s\n", err, ci_str_network_error((int)err, buf, sizeof(buf)));
            return -1;
	}
    }
    return 0;
}

int ci_read(ci_socket fd, void *buf, size_t count, int timeout)
{
    int bytes = 0, err = 0;

    do {
        bytes = recv(fd, buf, count, 0);
    } while (bytes == SOCKET_ERROR && (err = WSAGetLastError()) == WSAEINTR);

    if (bytes == SOCKET_ERROR && err == WSAEWOULDBLOCK) {
        int ret;
        do {
            ret = ci_wait_for_data(fd, timeout, wait_for_read);
        } while (ret & ci_wait_should_retry);

        if (ret <= 0)  /*timeout or connection closed*/
            return -1;

        do {
            bytes = recv(fd, buf, count, 0);
        } while (bytes == SOCKET_ERROR
                 && (err = WSAGetLastError()) == WSAEINTR);
    }
    if (bytes == 0) {
        return -1;
    }
    return bytes;
}

int ci_write(ci_socket fd, const void *buf, size_t count, int timeout)
{
    int bytes = 0;
    int err = 0;
    int remains = count;
    char *b = (char *) buf;

    while (remains > 0) {      //write until count bytes written
        do {
            bytes = send(fd, b, remains, 0);
        } while (bytes == SOCKET_ERROR
                 && (err = WSAGetLastError()) == WSAEINTR);

        if (bytes == SOCKET_ERROR && err == WSAEWOULDBLOCK) {
             int ret;
            do {
                ret = ci_wait_for_data(fd, timeout, wait_for_write);
            } while (ret & ci_wait_should_retry);

            if (ret <= 0) /*timeout or connection closed*/
                return -1;

            do {
                bytes = send(fd, b, remains, 0);
            } while (bytes == SOCKET_ERROR
                     && (err = WSAGetLastError()) == WSAEINTR);

        }
        if (bytes < 0)
            return bytes;
        b = b + bytes;        //points to remaining bytes......
        remains = remains - bytes;
    }                          //Ok......

    return count;
}

int ci_read_nonblock(ci_socket fd, void *buf, size_t count)
{
    int bytes = 0;
    do {
        bytes = recv(fd, buf, count, 0);
    } while (bytes == SOCKET_ERROR && WSAGetLastError() == WSAEINTR);

    if (bytes < 0 && WSAGetLastError() == WSAEWOULDBLOCK)
        return 0;

    if (bytes == 0) { /*EOF received?*/
        ci_debug_printf(4, "Zero bytes read. Is it after wait for data?\n");
        return -1;
    }

    return bytes;
}

int ci_write_nonblock(ci_socket fd, const void *buf, size_t count)
{
    int bytes = 0;
    do {
        bytes = send(fd, buf, count, 0);
    } while (bytes == SOCKET_ERROR && WSAGetLastError() == WSAEINTR);

    if (bytes < 0 && WSAGetLastError() == WSAEWOULDBLOCK)
        return 0;

    if (bytes == 0) /*connection is closed?*/
        return -1;

    return bytes;
}

int ci_linger_close(ci_socket fd, int timeout)
{
    char buf[10];
    int ret;
    ci_debug_printf(1, "Waiting to close connection\n");

    if (shutdown(fd, SD_SEND) != 0) {
        closesocket(fd);
        return 1;
    }

    while (ci_wait_for_data(fd, timeout, wait_for_read)
            && (ret = ci_read_nonblock(fd, buf, 10)) > 0)
        ci_debug_printf(1, "OK I linger %d bytes.....\n", ret);

    closesocket(fd);
    ci_debug_printf(1, "Connection closed ...\n");
    return 1;
}

int ci_hard_close(ci_socket fd)
{
    closesocket(fd);
    return 1;
}

ci_socket_t ci_socket_connect(ci_sockaddr_t *srvaddr, int *errcode)
{
    unsigned int addrlen = 0;
    ci_socket_t s;
    s = socket(srvaddr->ci_sin_family, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
        return INVALID_SOCKET;

#ifdef USE_IPV6
    if (srvaddr->ci_sin_family == AF_INET6)
        addrlen = sizeof(struct sockaddr_in6);
    else
#endif
        addrlen = sizeof(struct sockaddr_in);

    // Sets the fd to non-block mode
    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    int ret;
    ret = connect(s, (struct sockaddr *) &(srvaddr->sockaddr), addrlen);
    if (ret == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSAEINPROGRESS && error != WSAEWOULDBLOCK && error != WSAEINVAL) {
            closesocket(s);
            s = INVALID_SOCKET;
        }
    }
    return s;
}

int ci_socket_connected_ok(ci_socket_t s)
{
    int errcode = 0;
    int len = sizeof(errcode);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&errcode, &len) != 0)
        errcode = errno;
    return errcode;
}
