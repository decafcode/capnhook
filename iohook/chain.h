#include <windows.h>

#include "iohook/irp.h"

void iohook_chain_init(void);
HRESULT iohook_chain_push_handler(iohook_fn_t fn);
HRESULT iohook_chain_invoke_next(struct irp *irp);
