#pragma once

#include <windows.h>

#include <stddef.h>
#include <stdint.h>

#include "iohook/irp.h"

HANDLE iohook_open_dummy_fd(void)
#ifdef __GNUC__
__attribute__((deprecated("Use iohook_open_nul_fd instead")))
#endif
;

HRESULT iohook_open_nul_fd(HANDLE *fd);
HRESULT iohook_push_handler(iohook_fn_t fn);
HRESULT iohook_invoke_next(struct irp *irp);
