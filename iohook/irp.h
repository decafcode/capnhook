#pragma once

#include <windows.h>

#include <stddef.h>
#include <stdint.h>

#include "iohook/iobuf.h"

enum irp_op {
    /* File I/O */

    IRP_OP_OPEN,
    IRP_OP_CLOSE,
    IRP_OP_READ,
    IRP_OP_WRITE,
    IRP_OP_IOCTL,
    IRP_OP_FSYNC,
    IRP_OP_SEEK,

    /* Socket I/O */

    IRP_OP_SOCKET,
    IRP_OP_CLOSESOCKET,
    IRP_OP_BIND,
    IRP_OP_CONNECT,
    IRP_OP_LISTEN,
    IRP_OP_ACCEPT,
    IRP_OP_RECVFROM,
    IRP_OP_SENDTO,
    IRP_OP_IOCTLSOCKET,
    IRP_OP_GETSOCKNAME,
    IRP_OP_GETPEERNAME,
    IRP_OP_GETSOCKOPT,
    IRP_OP_SETSOCKOPT,
};

struct irp {
    /* Common */

    enum irp_op op;
    size_t next_handler;
    HANDLE fd;
    OVERLAPPED *ovl;
    LPOVERLAPPED_COMPLETION_ROUTINE completion;
    struct const_iobuf write;
    struct iobuf read;

    /* File I/O */

    uint32_t ioctl;
    const wchar_t *open_filename;
    uint32_t open_access;
    uint32_t open_share;
    SECURITY_ATTRIBUTES *open_sa;
    uint32_t open_creation;
    uint32_t open_flags;
    HANDLE *open_tmpl;
    uint32_t seek_origin;
    int64_t seek_offset;
    uint64_t seek_pos;

    /* Socket I/O */

    int sock_af;
    int sock_type;
    int sock_protocol;
    int listen_backlog;
    uint32_t sock_flags;
    const struct sockaddr *addr_out;
    int addr_out_len;
    struct sockaddr *addr_in;
    int *addr_in_len;
    HANDLE accepted_fd;
    int sock_ioctl;
    u_long *sock_ioctl_param;
    int sockopt_level;
    int sockopt_name;
};

typedef HRESULT (*iohook_fn_t)(struct irp *irp);
