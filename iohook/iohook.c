#include <windows.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hook/table.h"

#include "iohook/chain.h"
#include "iohook/file.h"
#include "iohook/iohook.h"
#include "iohook/socket-io.h"
#include "iohook/socket-mgmt.h"

static void iohook_init(void);
static HRESULT iohook_invoke_real(struct irp *irp);

static const iohook_fn_t iohook_real_handlers[] = {
    /* File ops */

    [IRP_OP_OPEN]           = iohook_invoke_real_open,
    [IRP_OP_CLOSE]          = iohook_invoke_real_close,
    [IRP_OP_READ]           = iohook_invoke_real_read,
    [IRP_OP_WRITE]          = iohook_invoke_real_write,
    [IRP_OP_SEEK]           = iohook_invoke_real_seek,
    [IRP_OP_FSYNC]          = iohook_invoke_real_fsync,
    [IRP_OP_IOCTL]          = iohook_invoke_real_ioctl,

    /* Socket ops */

    [IRP_OP_SOCKET]         = iohook_invoke_real_socket,
    [IRP_OP_CLOSESOCKET]    = iohook_invoke_real_closesocket,
    [IRP_OP_BIND]           = iohook_invoke_real_bind,
    [IRP_OP_CONNECT]        = iohook_invoke_real_connect,
    [IRP_OP_LISTEN]         = iohook_invoke_real_listen,
    [IRP_OP_ACCEPT]         = iohook_invoke_real_accept,
    [IRP_OP_RECVFROM]       = iohook_invoke_real_recvfrom,
    [IRP_OP_SENDTO]         = iohook_invoke_real_sendto,
    [IRP_OP_IOCTLSOCKET]    = iohook_invoke_real_ioctlsocket,
    [IRP_OP_GETSOCKNAME]    = iohook_invoke_real_getsockname,
    [IRP_OP_GETPEERNAME]    = iohook_invoke_real_getpeername,
    [IRP_OP_GETSOCKOPT]     = iohook_invoke_real_getsockopt,
    [IRP_OP_SETSOCKOPT]     = iohook_invoke_real_setsockopt,
};

static bool iohook_initted;

static void iohook_init(void)
{
    /* Permit repeated initializations. This isn't atomic because the whole IAT
       insertion dance is extremely non-atomic to begin with. */

    if (iohook_initted) {
        return;
    }

    iohook_chain_init();
    iohook_file_hook_apis();
    iohook_socket_io_hook_apis();
    iohook_socket_mgmt_hook_apis();
    iohook_chain_push_handler(iohook_invoke_real);
    iohook_initted = true;
}

// Deprecated
HANDLE iohook_open_dummy_fd(void)
{
    HANDLE result;
    HRESULT hr;

    iohook_init();
    hr = iohook_file_open_nul_fd(&result);

    return FAILED(hr) ? INVALID_HANDLE_VALUE : result;
}

HRESULT iohook_open_nul_fd(HANDLE *out)
{
    assert(out != NULL);

    iohook_init();

    return iohook_file_open_nul_fd(out);
}

HRESULT iohook_push_handler(iohook_fn_t fn)
{
    iohook_init();

    return iohook_chain_push_handler(fn);
}

HRESULT iohook_invoke_next(struct irp *irp)
{
    assert(iohook_initted);

    return iohook_chain_invoke_next(irp);
}

static HRESULT iohook_invoke_real(struct irp *irp)
{
    iohook_fn_t handler;

    assert(irp != NULL);
    assert(irp->op < _countof(iohook_real_handlers));

    handler = iohook_real_handlers[irp->op];

    assert(handler != NULL);

    return handler(irp);
}
