#pragma once

#include <windows.h>

#include "iohook/irp.h"

void iohook_file_hook_apis(void);
HRESULT iohook_file_open_nul_fd(HANDLE *out);
HRESULT iohook_invoke_real_open(struct irp *irp);
HRESULT iohook_invoke_real_close(struct irp *irp);
HRESULT iohook_invoke_real_read(struct irp *irp);
HRESULT iohook_invoke_real_write(struct irp *irp);
HRESULT iohook_invoke_real_seek(struct irp *irp);
HRESULT iohook_invoke_real_fsync(struct irp *irp);
HRESULT iohook_invoke_real_ioctl(struct irp *irp);
