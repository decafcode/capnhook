#pragma once

#include "iohook/irp.h"

void iohook_socket_io_hook_apis(void);
HRESULT iohook_invoke_real_recvfrom(struct irp *irp);
HRESULT iohook_invoke_real_sendto(struct irp *irp);
