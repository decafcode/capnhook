#include <windows.h>
#include <winsock2.h>

#include "hook/hr.h"
#include "hook/table.h"

#include "iohook/chain.h"
#include "iohook/irp.h"
#include "iohook/socket-io.h"

/* Hooks */
static int WSAAPI iohook_recvfrom(
        SOCKET s,
        char *buf,
        int len,
        int flags,
        struct sockaddr *from,
        int *fromlen);

static int WSAAPI iohook_sendto(
        SOCKET s,
        const char *buf,
        int len,
        int flags,
        const struct sockaddr *to,
        int tolen);

/* Links */

static int (WSAAPI *next_recvfrom)(
        SOCKET s,
        char *buf,
        int len,
        int flags,
        struct sockaddr *from,
        int *fromlen);

static int (WSAAPI *next_sendto)(
        SOCKET s,
        const char *buf,
        int len,
        int flags,
        const struct sockaddr *to,
        int tolen);

static const struct hook_symbol iohook_socket_io_ws2_32_syms[] = {
    {
        .name       = "recvfrom",
        .ordinal    = 17,
        .patch      = iohook_recvfrom,
        .link       = (void *) &next_recvfrom,
    }, {
        .name       = "sendto",
        .ordinal    = 20,
        .patch      = iohook_sendto,
        .link       = (void *) &next_sendto,
    }
};

void iohook_socket_io_hook_apis(void)
{
    hook_table_apply(
            NULL,
            "ws2_32.dll",
            iohook_socket_io_ws2_32_syms,
            _countof(iohook_socket_io_ws2_32_syms));
}

HRESULT iohook_invoke_real_recvfrom(struct irp *irp)
{
    int result;

    assert(irp != NULL);

    result = next_recvfrom(
            (SOCKET) irp->fd,
            (char *) irp->read.bytes,
            irp->read.nbytes,
            irp->sock_flags,
            irp->addr_in,
            irp->addr_in_len);

    if (result < 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    irp->read.pos = result;

    return S_OK;
}

HRESULT iohook_invoke_real_sendto(struct irp *irp)
{
    int result;

    assert(irp != NULL);

    result = next_sendto(
            (SOCKET) irp->fd,
            (const char *) irp->write.bytes,
            irp->write.nbytes,
            irp->sock_flags,
            irp->addr_out,
            irp->addr_out_len);

    if (result < 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    irp->write.pos = result;

    return S_OK;
}


static int WSAAPI iohook_recvfrom(
        SOCKET s,
        char *buf,
        int len,
        int flags,
        struct sockaddr *from,
        int *fromlen)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET || buf == NULL || len < 0) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (from != NULL && fromlen == NULL) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (fromlen != NULL && *fromlen < 0) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_RECVFROM;
    irp.fd = (HANDLE) s;
    irp.read.bytes = (uint8_t *) buf;
    irp.read.nbytes = len;
    irp.sock_flags = flags;
    irp.addr_in = from;
    irp.addr_in_len = fromlen;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    SetLastError(ERROR_SUCCESS);

    return irp.read.pos;
}

static int WSAAPI iohook_sendto(
        SOCKET s,
        const char *buf,
        int len,
        int flags,
        const struct sockaddr *to,
        int tolen)
{
    struct irp irp;
    HRESULT hr;

    if (s == 0 || s == INVALID_SOCKET || buf == NULL || len < 0) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (tolen < 0) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_SENDTO;
    irp.fd = (HANDLE) s;
    irp.write.bytes = (const uint8_t *) buf;
    irp.write.nbytes = len;
    irp.sock_flags = flags;
    irp.addr_out = to;
    irp.addr_out_len = tolen;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    SetLastError(ERROR_SUCCESS);

    return irp.write.pos;
}
