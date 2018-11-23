#include <windows.h>

#ifdef __GNUC__
#include <ntdef.h>
#else
#include <winnt.h>
#endif
#include <devioctl.h>
#include <ntddser.h>

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "hook/iobuf.h"
#include "hook/iohook.h"

#include "hooklib/uart.h"

static HRESULT uart_handle_open(struct uart *uart, struct irp *irp);
static HRESULT uart_handle_close(struct uart *uart, struct irp *irp);
static HRESULT uart_handle_read(struct uart *uart, struct irp *irp);
static HRESULT uart_handle_write(struct uart *uart, struct irp *irp);
static HRESULT uart_handle_ioctl(struct uart *uart, struct irp *irp);

void uart_init(struct uart *uart, unsigned int port_no)
{
    assert(uart != NULL);
    assert(port_no > 0);

    uart->fd = NULL;
    uart->port_no = port_no;

    uart->baud.BaudRate = 115200;

    memset(&uart->status, 0, sizeof(uart->status));

    uart->chars.EofChar = 0x00;
    uart->chars.ErrorChar = 0x00;
    uart->chars.BreakChar = 0x00;
    uart->chars.EventChar = 0x00;
    uart->chars.XonChar = 0x11;
    uart->chars.XoffChar = 0x13;

    memset(&uart->handflow, 0, sizeof(uart->handflow));

    uart->line.StopBits = STOP_BIT_1;
    uart->line.Parity = NO_PARITY;
    uart->line.WordLength = 8;

    memset(&uart->timeouts, 0, sizeof(uart->timeouts));

    uart->mask = 0;

    memset(&uart->written, 0, sizeof(uart->written));
    memset(&uart->readable, 0, sizeof(uart->readable));
}

void uart_fini(struct uart *uart)
{
    struct irp irp;

    assert(uart != NULL);

    if (uart->fd != NULL) {
        memset(&irp, 0, sizeof(irp));
        irp.op = IRP_OP_CLOSE;
        irp.fd = uart->fd;

        /* Not much we can do if this fails */
        iohook_invoke_next(&irp);
    }
}

bool uart_match_irp(const struct uart *uart, const struct irp *irp)
{
    const wchar_t *path;
    unsigned int port_no;
    wchar_t wc;
    size_t i;

    if (irp->op == IRP_OP_OPEN) {
        /* Win32 device nodes can unfortunately be identified using a variety
           of different syntax */

        path = irp->open_filename;

        if (    wcsncmp(path, L"\\\\.\\", 4) == 0 ||
                wcsncmp(path, L"\\\\?\\", 4) == 0 ||
                wcsncmp(path, L"\\??\\",  4) == 0 ) {
            /* NT style */

            path = path + 4;

            if (    (path[0] & ~0x20) != L'C' ||
                    (path[1] & ~0x20) != L'O' ||
                    (path[2] & ~0x20) != L'M' ) {
                return false;
            }

            port_no = 0;

            for (i = 3 ; path[i] ; i++) {
                wc = path[i];

                if (wc < L'0' || wc > L'9') {
                    return false;
                }

                port_no *= 10;
                port_no += wc - L'0';
            }
        } else {
            /* DOS style. Only COM1 through COM9 are supported. */

            if (    (path[0] & ~0x20) != L'C' ||
                    (path[1] & ~0x20) != L'O' ||
                    (path[2] & ~0x20) != L'M' ||
                    (path[3] < L'1' || path[3] > L'9') ) {
                return false;
            }

            /* DOS-style COM port names are allowed to have an optional trailing
               colon, as if this wasn't complicated enough. */

            if (    (path[4] != L'\0') &&
                    (path[4] != L':' || path[5] != L'\0') ) {
                return false;
            }

            port_no = path[3] - L'0';
        }

        return port_no == uart->port_no;
    } else {
        /* All other IRPs are matched by checking the file descriptor. */

        return irp->fd == uart->fd;
    }
}

HRESULT uart_handle_irp(struct uart *uart, struct irp *irp)
{
    assert(uart != NULL);
    assert(irp != NULL);

    switch (irp->op) {
    case IRP_OP_OPEN:   return uart_handle_open(uart, irp);
    case IRP_OP_CLOSE:  return uart_handle_close(uart, irp);
    case IRP_OP_READ:   return uart_handle_read(uart, irp);
    case IRP_OP_WRITE:  return uart_handle_write(uart, irp);
    case IRP_OP_IOCTL:  return uart_handle_ioctl(uart, irp);
    case IRP_OP_FSYNC:  return S_OK;
    default:            return HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION);
    }
}

static HRESULT uart_handle_open(struct uart *uart, struct irp *irp)
{
    HRESULT hr;

    if (uart->fd != NULL) {
        /* Windows only allows one handle to be open for each COM port at a
           time. Strangely enough it returns an Access Denied error in this
           situation instead of something more appropriate. */

        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }

    /* Transform this open call so that it opens the NUL device, then pass it
       on. This gives us a real Win32 HANDLE distinct from all other open
       HANDLEs. */

    irp->open_filename = L"NUL";
    irp->open_access = GENERIC_READ | GENERIC_WRITE;
    irp->open_share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    irp->open_sa = NULL;
    irp->open_creation = OPEN_EXISTING;
    irp->open_flags = FILE_FLAG_OVERLAPPED;
    irp->open_tmpl = NULL;

    hr = iohook_invoke_next(irp);

    if (SUCCEEDED(hr)) {
        uart->fd = irp->fd;
    }

    return hr;
}

static HRESULT uart_handle_close(struct uart *uart, struct irp *irp)
{
    uart->fd = NULL;

    return iohook_invoke_next(irp);
}

static HRESULT uart_handle_read(struct uart *uart, struct irp *irp)
{
    /* This does a memmove() under the covers. Less efficient than a ring
       buffer, but I don't expect this to matter in the common case where the
       entire buffer gets drained, particularly since UARTs are decidedly
       low-speed devices anyway. */

    iobuf_shift(&irp->read, &uart->readable);

    return S_OK;
}

static HRESULT uart_handle_write(struct uart *uart, struct irp *irp)
{
    iobuf_move(&uart->written, &irp->write);

    return S_OK;
}

static HRESULT uart_handle_ioctl(struct uart *uart, struct irp *irp)
{
    switch (irp->ioctl) {
    case IOCTL_SERIAL_GET_BAUD_RATE:
        return iobuf_write(&irp->read, &uart->baud, sizeof(uart->baud));

    case IOCTL_SERIAL_GET_CHARS:
        return iobuf_write(&irp->read, &uart->chars, sizeof(uart->chars));

    case IOCTL_SERIAL_GET_COMMSTATUS:
        uart->status.AmountInInQueue = uart->readable.pos;
        uart->status.AmountInOutQueue = uart->written.pos;

        return iobuf_write(&irp->read, &uart->status, sizeof(uart->status));

    case IOCTL_SERIAL_GET_HANDFLOW:
        return iobuf_write(&irp->read, &uart->handflow, sizeof(uart->handflow));

    case IOCTL_SERIAL_GET_LINE_CONTROL:
        return iobuf_write(&irp->read, &uart->line, sizeof(uart->line));

    case IOCTL_SERIAL_GET_TIMEOUTS:
        return iobuf_write(&irp->read, &uart->timeouts, sizeof(uart->timeouts));

    case IOCTL_SERIAL_GET_WAIT_MASK:
        return iobuf_write(&irp->read, &uart->mask, sizeof(uart->mask));

    case IOCTL_SERIAL_SET_BAUD_RATE:
        return iobuf_read(&irp->write, &uart->baud, sizeof(uart->baud));

    case IOCTL_SERIAL_SET_CHARS:
        return iobuf_read(&irp->write, &uart->chars, sizeof(uart->chars));

    case IOCTL_SERIAL_SET_HANDFLOW:
        return iobuf_read(&irp->write, &uart->handflow, sizeof(uart->handflow));

    case IOCTL_SERIAL_SET_LINE_CONTROL:
        return iobuf_read(&irp->write, &uart->line, sizeof(uart->line));

    case IOCTL_SERIAL_SET_TIMEOUTS:
        return iobuf_read(&irp->write, &uart->timeouts, sizeof(uart->timeouts));

    case IOCTL_SERIAL_SET_WAIT_MASK:
        return iobuf_read(&irp->write, &uart->mask, sizeof(uart->mask));

    /* These can be safely ignored */
    case IOCTL_SERIAL_SET_BREAK_ON:
    case IOCTL_SERIAL_SET_BREAK_OFF:
    case IOCTL_SERIAL_CLR_DTR:
    case IOCTL_SERIAL_CLR_RTS:
    case IOCTL_SERIAL_SET_DTR:
    case IOCTL_SERIAL_SET_RTS:
    case IOCTL_SERIAL_SET_XOFF:
    case IOCTL_SERIAL_SET_XON:

    case IOCTL_SERIAL_PURGE:
    case IOCTL_SERIAL_SET_QUEUE_SIZE:
        return S_OK;

    default:
        return HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION);
    }
}
