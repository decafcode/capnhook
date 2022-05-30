#include <windows.h>
#include <winsock2.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "hook/hr.h"
#include "hook/table.h"

#include "iohook/chain.h"
#include "iohook/irp.h"
#include "iohook/socket-mgmt.h"

/* Hooks */

static SOCKET WSAAPI iohook_socket(int af, int type, int protocol);

static int WSAAPI iohook_closesocket(SOCKET s);

static int WSAAPI iohook_bind(
        SOCKET s,
        const struct sockaddr *name,
        int namelen);

static int WSAAPI iohook_connect(
        SOCKET s,
        const struct sockaddr *name,
        int namelen);

static int WSAAPI iohook_listen(SOCKET s, int backlog);

static SOCKET WSAAPI iohook_accept(
        SOCKET s,
        struct sockaddr *addr,
        int *addrlen);

static int WSAAPI iohook_ioctlsocket(SOCKET s, long cmd, u_long *argp);

static int WSAAPI iohook_getsockname(
        SOCKET s,
        struct sockaddr *name,
        int *namelen);

static int WSAAPI iohook_getpeername(
        SOCKET s,
        struct sockaddr *name,
        int *namelen);

static int WSAAPI iohook_getsockopt(
        SOCKET s,
        int level,
        int optname,
        char *optval,
        int *optlen);

static int WSAAPI iohook_setsockopt(
        SOCKET s,
        int level,
        int optname,
        const char *optval,
        int optlen);

/* Links */

static SOCKET (WSAAPI *next_socket)(int af, int type, int protocol);

static BOOL (WSAAPI *next_closesocket)(SOCKET s);

static int (WSAAPI *next_bind)(
        SOCKET s,
        const struct sockaddr *name,
        int namelen);

static int (WSAAPI *next_connect)(
        SOCKET s,
        const struct sockaddr *name,
        int namelen);

static int (WSAAPI *next_listen)(SOCKET s, int backlog);

static SOCKET (WSAAPI *next_accept)(
        SOCKET s,
        struct sockaddr *addr,
        int *addrlen);

static int (WSAAPI *next_ioctlsocket)(
        SOCKET s,
        long cmd,
        u_long *argp);

static int (WSAAPI *next_getsockname)(
        SOCKET s,
        struct sockaddr *name,
        int *namelen);

static int (WSAAPI *next_getpeername)(
        SOCKET s,
        struct sockaddr *name,
        int *namelen);

static int (WSAAPI *next_getsockopt)(
        SOCKET s,
        int level,
        int optname,
        char *optval,
        int *optlen);

static int (WSAAPI *next_setsockopt)(
        SOCKET s,
        int level,
        int optname,
        const char *optval,
        int optlen);

static const struct hook_symbol iohook_socket_mgmt_ws2_32_syms[] = {
    {
        .name       = "socket",
        .ordinal    = 23,
        .patch      = iohook_socket,
        .link       = (void *) &next_socket,
    }, {
        .name       = "closesocket",
        .ordinal    = 3,
        .patch      = iohook_closesocket,
        .link       = (void *) &next_closesocket,
    }, {
        .name       = "bind",
        .ordinal    = 2,
        .patch      = iohook_bind,
        .link       = (void *) &next_bind,
    }, {
        .name       = "connect",
        .ordinal    = 4,
        .patch      = iohook_connect,
        .link       = (void *) &next_connect,
    }, {
        .name       = "listen",
        .ordinal    = 13,
        .patch      = iohook_listen,
        .link       = (void *) &next_listen,
    }, {
        .name       = "accept",
        .ordinal    = 1,
        .patch      = iohook_accept,
        .link       = (void *) &next_accept,
    }, {
        .name       = "ioctlsocket",
        .ordinal    = 10,
        .patch      = iohook_ioctlsocket,
        .link       = (void *) &next_ioctlsocket,
    }, {
        .name       = "getsockname",
        .ordinal    = 6,
        .patch      = iohook_getsockname,
        .link       = (void *) &next_getsockname,
    }, {
        .name       = "getpeername",
        .ordinal    = 5,
        .patch      = iohook_getpeername,
        .link       = (void *) &next_getpeername,
    }, {
        .name       = "getsockopt",
        .ordinal    = 7,
        .patch      = iohook_getsockopt,
        .link       = (void *) &next_getsockopt,
    }, {
        .name       = "setsockopt",
        .ordinal    = 21,
        .patch      = iohook_setsockopt,
        .link       = (void *) &next_setsockopt,
    }
};

void iohook_socket_mgmt_hook_apis(void)
{
    hook_table_apply(
            NULL,
            "ws2_32.dll",
            iohook_socket_mgmt_ws2_32_syms,
            _countof(iohook_socket_mgmt_ws2_32_syms));
}

HRESULT iohook_invoke_real_socket(struct irp *irp)
{
    SOCKET s;

    assert(irp != NULL);

    s = next_socket(irp->sock_af, irp->sock_type, irp->sock_protocol);

    if (s == INVALID_SOCKET) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    irp->fd = (HANDLE) s;

    return S_OK;
}

HRESULT iohook_invoke_real_closesocket(struct irp *irp)
{
    int result;

    assert(irp != NULL);

    result = next_closesocket((SOCKET) irp->fd);

    if (result != 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT iohook_invoke_real_bind(struct irp *irp)
{
    int result;

    assert(irp != NULL);

    result = next_bind((SOCKET) irp->fd, irp->addr_out, irp->addr_out_len);

    if (result != 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT iohook_invoke_real_connect(struct irp *irp)
{
    int result;

    assert(irp != NULL);

    result = next_connect((SOCKET) irp->fd, irp->addr_out, irp->addr_out_len);

    if (result != 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT iohook_invoke_real_listen(struct irp *irp)
{
    int result;

    assert(irp != NULL);

    result = next_listen((SOCKET) irp->fd, irp->listen_backlog);

    if (result < 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT iohook_invoke_real_accept(struct irp *irp)
{
    SOCKET result;

    assert(irp != NULL);

    result = next_accept((SOCKET) irp->fd, irp->addr_in, irp->addr_in_len);

    if (result == INVALID_SOCKET) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    irp->accepted_fd = (HANDLE) result;

    return S_OK;
}

HRESULT iohook_invoke_real_ioctlsocket(struct irp *irp)
{
    int result;

    assert(irp != NULL);

    result = next_ioctlsocket(
            (SOCKET) irp->fd,
            irp->sock_ioctl,
            irp->sock_ioctl_param);

    if (result < 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT iohook_invoke_real_getsockname(struct irp *irp)
{
    int result;

    assert(irp != NULL);

    result = next_getsockname(
            (SOCKET) irp->fd,
            irp->addr_in,
            irp->addr_in_len);

    if (result < 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT iohook_invoke_real_getpeername(struct irp *irp)
{
    int result;

    assert(irp != NULL);

    result = next_getpeername(
            (SOCKET) irp->fd,
            irp->addr_in,
            irp->addr_in_len);

    if (result < 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT iohook_invoke_real_getsockopt(struct irp *irp)
{
    int result;
    int optlen;

    assert(irp != NULL);
    assert(irp->read.pos == 0);

    optlen = irp->read.nbytes;
    result = next_getsockopt(
            (SOCKET) irp->fd,
            irp->sockopt_level,
            irp->sockopt_name,
            (char *) irp->read.bytes,
            &optlen);

    if (result < 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    irp->read.pos = optlen;

    return S_OK;
}

HRESULT iohook_invoke_real_setsockopt(struct irp *irp)
{
    int result;

    assert(irp != NULL);
    assert(irp->write.pos == 0);

    result = next_setsockopt(
            (SOCKET) irp->fd,
            irp->sockopt_level,
            irp->sockopt_name,
            (const char *) irp->write.bytes,
            irp->write.nbytes);

    if (result < 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

static SOCKET WSAAPI iohook_socket(int af, int type, int protocol)
{
    struct irp irp;
    HRESULT hr;

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_SOCKET;
    irp.fd = (HANDLE) INVALID_SOCKET;
    irp.sock_af = af;
    irp.sock_type = type;
    irp.sock_protocol = protocol;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, INVALID_SOCKET);
    }

    SetLastError(ERROR_SUCCESS);

    return (SOCKET) irp.fd;
}

static int WSAAPI iohook_closesocket(SOCKET s)
{
    struct irp irp;
    HRESULT hr;

    if (s < 0 || s == INVALID_SOCKET) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_CLOSESOCKET;
    irp.fd = (HANDLE) s;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    SetLastError(ERROR_SUCCESS);

    return 0;
}

static int WSAAPI iohook_bind(
        SOCKET s,
        const struct sockaddr *name,
        int namelen)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET || name == NULL) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_BIND;
    irp.fd = (HANDLE) s;
    irp.addr_out = name;
    irp.addr_out_len = namelen;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    SetLastError(ERROR_SUCCESS);

    return 0;
}

static int WSAAPI iohook_connect(
        SOCKET s,
        const struct sockaddr *name,
        int namelen)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET || name == NULL) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_CONNECT;
    irp.fd = (HANDLE) s;
    irp.addr_out = name;
    irp.addr_out_len = namelen;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    SetLastError(ERROR_SUCCESS);

    return 0;
}

static int WSAAPI iohook_listen(SOCKET s, int backlog)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET || backlog < 0) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_LISTEN;
    irp.fd = (HANDLE) s;
    irp.listen_backlog = backlog;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    SetLastError(ERROR_SUCCESS);

    return 0;
}

static SOCKET WSAAPI iohook_accept(
        SOCKET s,
        struct sockaddr *addr,
        int *addrlen)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET || addr == NULL || addrlen == NULL) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_ACCEPT;
    irp.fd = (HANDLE) s;
    irp.addr_in = addr;
    irp.addr_in_len = addrlen;
    irp.accepted_fd = (HANDLE) INVALID_SOCKET;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, INVALID_SOCKET);
    }

    SetLastError(ERROR_SUCCESS);

    return (SOCKET) irp.accepted_fd;
}

static int WSAAPI iohook_ioctlsocket(SOCKET s, long cmd, u_long *argp)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTLSOCKET;
    irp.fd = (HANDLE) s;
    irp.sock_ioctl = cmd;
    irp.sock_ioctl_param = argp;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    SetLastError(ERROR_SUCCESS);

    return 0;
}

static int WSAAPI iohook_getsockname(
        SOCKET s,
        struct sockaddr *name,
        int *namelen)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET || name == NULL || namelen == NULL) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (*namelen < 0) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_GETSOCKNAME;
    irp.fd = (HANDLE) s;
    irp.addr_in = name;
    irp.addr_in_len = namelen;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    SetLastError(ERROR_SUCCESS);

    return 0;
}

static int WSAAPI iohook_getpeername(
        SOCKET s,
        struct sockaddr *name,
        int *namelen)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET || name == NULL || namelen == NULL) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (*namelen < 0) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_GETPEERNAME;
    irp.fd = (HANDLE) s;
    irp.addr_in = name;
    irp.addr_in_len = namelen;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    SetLastError(ERROR_SUCCESS);

    return 0;
}

static int WSAAPI iohook_getsockopt(
        SOCKET s,
        int level,
        int optname,
        char *optval,
        int *optlen)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET || optval == NULL || optlen == NULL) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_GETSOCKOPT;
    irp.fd = (HANDLE) s;
    irp.read.bytes = (uint8_t *) optval;
    irp.read.nbytes = *optlen;
    irp.sockopt_level = level;
    irp.sockopt_name = optname;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    *optlen = irp.read.pos;
    SetLastError(ERROR_SUCCESS);

    return 0;
}

static int WSAAPI iohook_setsockopt(
        SOCKET s,
        int level,
        int optname,
        const char *optval,
        int optlen)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET || optval == NULL) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_SETSOCKOPT;
    irp.fd = (HANDLE) s;
    irp.write.bytes = (const uint8_t *) optval;
    irp.write.nbytes = optlen;
    irp.sockopt_level = level;
    irp.sockopt_name = optname;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    SetLastError(ERROR_SUCCESS);

    return 0;
}
