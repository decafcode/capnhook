#include <windows.h>

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "iohook/chain.h"
#include "iohook/irp.h"

static CRITICAL_SECTION iohook_chain_lock;
static iohook_fn_t *iohook_chain_handlers;
static size_t iohook_chain_nhandlers;

void iohook_chain_init(void)
{
    InitializeCriticalSection(&iohook_chain_lock);
}

HRESULT iohook_chain_push_handler(iohook_fn_t fn)
{
    iohook_fn_t *new_array;
    size_t new_size;
    HRESULT hr;

    assert(fn != NULL);

    iohook_chain_init();
    EnterCriticalSection(&iohook_chain_lock);

    new_size = iohook_chain_nhandlers + 1;
    new_array = malloc(new_size * sizeof(iohook_fn_t));

    if (new_array != NULL) {
        new_array[0] = fn;
        memcpy( &new_array[1],
                iohook_chain_handlers,
                iohook_chain_nhandlers * sizeof(iohook_fn_t));
        free(iohook_chain_handlers);
        iohook_chain_handlers = new_array;
        iohook_chain_nhandlers = new_size;
        hr = S_OK;
    } else {
        hr = E_OUTOFMEMORY;
    }

    LeaveCriticalSection(&iohook_chain_lock);

    return hr;
}

HRESULT iohook_chain_invoke_next(struct irp *irp)
{
    iohook_fn_t handler;
    HRESULT hr;

    assert(irp != NULL);

    EnterCriticalSection(&iohook_chain_lock);

    assert(irp->next_handler < iohook_chain_nhandlers);

    handler = iohook_chain_handlers[irp->next_handler];
    irp->next_handler++;

    LeaveCriticalSection(&iohook_chain_lock);

    hr = handler(irp);

    if (FAILED(hr)) {
        irp->next_handler = (size_t) -1;
    }

    return hr;
}
