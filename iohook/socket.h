#pragma once

#include "iohook/irp.h"

void iohook_socket_hook_apis(void);
HRESULT iohook_invoke_real_socket(struct irp *irp);
HRESULT iohook_invoke_real_closesocket(struct irp *irp);
HRESULT iohook_invoke_real_bind(struct irp *irp);
HRESULT iohook_invoke_real_connect(struct irp *irp);
HRESULT iohook_invoke_real_listen(struct irp *irp);
HRESULT iohook_invoke_real_accept(struct irp *irp);
HRESULT iohook_invoke_real_recvfrom(struct irp *irp);
HRESULT iohook_invoke_real_sendto(struct irp *irp);
HRESULT iohook_invoke_real_ioctlsocket(struct irp *irp);
HRESULT iohook_invoke_real_getsockname(struct irp *irp);
HRESULT iohook_invoke_real_getpeername(struct irp *irp);
HRESULT iohook_invoke_real_getsockopt(struct irp *irp);
HRESULT iohook_invoke_real_setsockopt(struct irp *irp);
