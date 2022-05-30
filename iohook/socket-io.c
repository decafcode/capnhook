#include <windows.h>
#include <winsock2.h>

#include "hook/hr.h"
#include "hook/table.h"

#include "iohook/async.h"
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

static int WSAAPI iohook_WSARecvFrom(
        SOCKET s,
        WSABUF *dests,
        uint32_t ndests,
        uint32_t *nbytes,
        uint32_t *flags,
        struct sockaddr *from,
        int *from_len,
        WSAOVERLAPPED *ovl,
        LPOVERLAPPED_COMPLETION_ROUTINE completion);

static int WSAAPI iohook_WSARecvFrom_valid(
        SOCKET s,
        WSABUF *dests,
        uint32_t ndests,
        uint32_t *nbytes,
        uint32_t *flags,
        struct sockaddr *from,
        int *from_len,
        WSAOVERLAPPED *ovl,
        LPOVERLAPPED_COMPLETION_ROUTINE completion);

static int WSAAPI iohook_WSASendTo(
        SOCKET s,
        WSABUF *srcs,
        uint32_t nsrcs,
        uint32_t *nbytes,
        uint32_t flags,
        const struct sockaddr *to,
        int to_len,
        OVERLAPPED *ovl,
        LPOVERLAPPED_COMPLETION_ROUTINE completion);

static int WSAAPI iohook_WSASendTo_valid(
        SOCKET s,
        WSABUF *srcs,
        uint32_t nsrcs,
        uint32_t *nbytes,
        uint32_t flags,
        const struct sockaddr *to,
        int to_len,
        OVERLAPPED *ovl,
        LPOVERLAPPED_COMPLETION_ROUTINE completion);

/* Links */

static int WSAAPI (*next_WSARecvFrom)(
        SOCKET s,
        WSABUF *dests,
        uint32_t ndests,
        uint32_t *nbytes,
        uint32_t *flags,
        struct sockaddr *from,
        int *from_len,
        WSAOVERLAPPED *ovl,
        LPOVERLAPPED_COMPLETION_ROUTINE completion);

static int WSAAPI (*next_WSASendTo)(
        SOCKET s,
        WSABUF *srcs,
        uint32_t nsrcs,
        uint32_t *nbytes,
        uint32_t flags,
        const struct sockaddr *to,
        int to_len,
        OVERLAPPED *ovl,
        LPOVERLAPPED_COMPLETION_ROUTINE completion);

static const struct hook_symbol iohook_socket_io_ws2_32_syms[] = {
    {
        .name       = "recvfrom",
        .ordinal    = 17,
        .patch      = iohook_recvfrom,
    }, {
        .name       = "sendto",
        .ordinal    = 20,
        .patch      = iohook_sendto,
    }, {
        .name       = "WSARecvFrom",
        .ordinal    = 73,
        .patch      = iohook_WSARecvFrom,
        .link       = (void *) &next_WSARecvFrom,
    }, {
        .name       = "WSASendTo",
        .ordinal    = 78,
        .patch      = iohook_WSASendTo,
        .link       = (void *) &next_WSASendTo,
    }
};

void iohook_socket_io_hook_apis(void)
{
    HMODULE ws2_32;

    hook_table_apply(
            NULL,
            "ws2_32.dll",
            iohook_socket_io_ws2_32_syms,
            _countof(iohook_socket_io_ws2_32_syms));

    /* Backfill "advanced" APIs which we use to invoke real socket IO ops,
       which the target application may or may not have imported. */

    ws2_32 = GetModuleHandleW(L"ws2_32.dll");

    if (ws2_32 != NULL) {
        if (next_WSARecvFrom == NULL) {
            next_WSARecvFrom = (void *) GetProcAddress(ws2_32, "WSARecvFrom");
        }

        if (next_WSASendTo == NULL) {
            next_WSASendTo = (void *) GetProcAddress(ws2_32, "WSASendTo");
        }
    }
}

HRESULT iohook_invoke_real_recvfrom(struct irp *irp)
{
    WSABUF dest;
    uint32_t nbytes;
    int result;

    assert(irp != NULL);

    dest.buf = (char *) &irp->read.bytes[irp->read.pos];
    dest.len = irp->read.nbytes - irp->read.pos;

    nbytes = 0;
    result = next_WSARecvFrom(
            (SOCKET) irp->fd,
            &dest,
            1,
            &nbytes,
            &irp->sock_flags,
            irp->addr_in,
            irp->addr_in_len,
            irp->ovl,
            irp->completion);

    if (result < 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    irp->read.pos += nbytes;

    return S_OK;
}
HRESULT iohook_invoke_real_sendto(struct irp *irp)
{
    WSABUF src;
    uint32_t nbytes;
    int result;

    assert(irp != NULL);

    /* Cast off buffer pointer's const qualifier when passing to WSABUF (but
       WSASendTo should treat this memory area as const) */

    src.buf = (char *) &irp->write.bytes[irp->write.pos];
    src.len = irp->write.nbytes - irp->write.pos;

    nbytes = 0;
    result = next_WSASendTo(
            (SOCKET) irp->fd,
            &src,
            1,
            &nbytes,
            irp->sock_flags,
            irp->addr_out,
            irp->addr_out_len,
            irp->ovl,
            irp->completion);

    if (result < 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    irp->write.pos = nbytes;

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

static int WSAAPI iohook_WSARecvFrom(
        SOCKET s,
        WSABUF *dests,
        uint32_t ndests,
        uint32_t *nbytes,
        uint32_t *flags,
        struct sockaddr *from,
        int *from_len,
        WSAOVERLAPPED *ovl,
        LPOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (ndests > 1) {
        /* capnhook can't do scatter-gather IO (yet?) */
        return next_WSARecvFrom(
                s,
                dests,
                ndests,
                nbytes,
                flags,
                from,
                from_len,
                ovl,
                completion);
    }

    if (s == 0 || s == INVALID_SOCKET) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (dests == NULL || ndests == 0) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (flags == NULL) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (from != NULL && from_len == NULL) { // && not ||
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (nbytes == NULL && ovl == NULL) { // && not ||
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    return iohook_WSARecvFrom_valid(
            s,
            dests,
            ndests,
            nbytes,
            flags,
            from,
            from_len,
            ovl,
            completion);
}

static int WSAAPI iohook_WSARecvFrom_valid(
        SOCKET s,
        WSABUF *dests,
        uint32_t ndests,
        uint32_t *nbytes,
        uint32_t *flags,
        struct sockaddr *from,
        int *from_len,
        WSAOVERLAPPED *ovl,
        LPOVERLAPPED_COMPLETION_ROUTINE completion)
{
    struct irp irp;
    HRESULT hr;
    BOOL ok;

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_RECVFROM;
    irp.fd = (HANDLE) s;
    irp.read.bytes = (uint8_t *) dests[0].buf;
    irp.read.nbytes = dests[0].len;
    irp.ovl = ovl;
    irp.completion = completion;
    irp.sock_flags = *flags;
    irp.addr_in = from;
    irp.addr_in_len = from_len;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    *flags = irp.sock_flags;

    ok = iohook_overlapped_result(nbytes, ovl, irp.read.pos);

    return ok ? 0 : SOCKET_ERROR;
}

static int WSAAPI iohook_WSASendTo(
        SOCKET s,
        WSABUF *srcs,
        uint32_t nsrcs,
        uint32_t *nbytes,
        uint32_t flags,
        const struct sockaddr *to,
        int to_len,
        OVERLAPPED *ovl,
        LPOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (nsrcs != 1) {
        /* capnhook can't do scatter-gather IO (yet?) */
        return next_WSASendTo(
                s,
                srcs,
                nsrcs,
                nbytes,
                flags,
                to,
                to_len,
                ovl,
                completion);
    }

    if (s == 0 || s == INVALID_SOCKET) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (srcs == NULL || nsrcs == 0) {
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    if (nbytes == NULL && ovl == NULL) { // && not ||
        SetLastError(WSAEINVAL);

        return SOCKET_ERROR;
    }

    return iohook_WSASendTo_valid(
            s,
            srcs,
            nsrcs,
            nbytes,
            flags,
            to,
            to_len,
            ovl,
            completion);
}

static int WSAAPI iohook_WSASendTo_valid(
        SOCKET s,
        WSABUF *srcs,
        uint32_t nsrcs,
        uint32_t *nbytes,
        uint32_t flags,
        const struct sockaddr *to,
        int to_len,
        OVERLAPPED *ovl,
        LPOVERLAPPED_COMPLETION_ROUTINE completion)
{
    struct irp irp;
    HRESULT hr;
    BOOL ok;

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_SENDTO;
    irp.fd = (HANDLE) s;
    irp.write.bytes = (const uint8_t *) srcs[0].buf;
    irp.write.nbytes = srcs[0].len;
    irp.ovl = ovl;
    irp.completion = completion;
    irp.sock_flags = flags;
    irp.addr_out = to;
    irp.addr_out_len = to_len;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, SOCKET_ERROR);
    }

    ok = iohook_overlapped_result(nbytes, ovl, irp.write.pos);

    return ok ? 0 : SOCKET_ERROR;
}
