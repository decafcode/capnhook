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

static void iohook_init(void);
static HRESULT iohook_invoke_real(struct irp *irp);

static const iohook_fn_t iohook_real_handlers[] = {
    [IRP_OP_OPEN]   = iohook_invoke_real_open,
    [IRP_OP_CLOSE]  = iohook_invoke_real_close,
    [IRP_OP_READ]   = iohook_invoke_real_read,
    [IRP_OP_WRITE]  = iohook_invoke_real_write,
    [IRP_OP_SEEK]   = iohook_invoke_real_seek,
    [IRP_OP_FSYNC]  = iohook_invoke_real_fsync,
    [IRP_OP_IOCTL]  = iohook_invoke_real_ioctl,
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
