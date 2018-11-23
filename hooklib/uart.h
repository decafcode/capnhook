#pragma once

#include <windows.h>

#ifdef __GNUC__
#include <ntdef.h>
#else
#include <winnt.h>
#endif
#include <devioctl.h>
#include <ntddser.h>

#include <stdbool.h>

#include "hook/iobuf.h"
#include "hook/iohook.h"

struct uart {
    HANDLE fd;
    unsigned int port_no;
    SERIAL_BAUD_RATE baud;
    SERIAL_STATUS status;
    SERIAL_CHARS chars;
    SERIAL_HANDFLOW handflow;
    SERIAL_LINE_CONTROL line;
    SERIAL_TIMEOUTS timeouts;
    DWORD mask;
    struct iobuf written;
    struct iobuf readable;
};

void uart_init(struct uart *uart, unsigned int port_no);
void uart_fini(struct uart *uart);
bool uart_match_irp(const struct uart *uart, const struct irp *irp);
HRESULT uart_handle_irp(struct uart *uart, struct irp *irp);
