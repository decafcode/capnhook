#include <windows.h>

#include <ntdef.h>
#include <devioctl.h>
#include <ntddser.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "hook/hr.h"
#include "hook/iohook.h"
#include "hook/table.h"

#include "hooklib/serial.h"

/* RS232 API hooks */

static BOOL WINAPI my_ClearCommBreak(HANDLE fd);
static BOOL WINAPI my_ClearCommError(
        HANDLE fd,
        uint32_t *errors,
        COMSTAT *status);
static BOOL WINAPI my_EscapeCommFunction(HANDLE fd, uint32_t func);
static BOOL WINAPI my_GetCommMask(HANDLE fd, uint32_t *out);
static BOOL WINAPI my_GetCommState(HANDLE fd, DCB *dcb);
static BOOL WINAPI my_GetCommTimeouts(HANDLE fd, COMMTIMEOUTS *dest);
static BOOL WINAPI my_PurgeComm(HANDLE fd, uint32_t flags);
static BOOL WINAPI my_SetCommMask(HANDLE fd, uint32_t mask);
static BOOL WINAPI my_SetCommState(HANDLE fd, const DCB *dcb);
static BOOL WINAPI my_SetCommTimeouts(HANDLE fd, COMMTIMEOUTS *timeouts);
static BOOL WINAPI my_SetupComm(HANDLE fd, uint32_t in_q, uint32_t out_q);
static BOOL WINAPI my_SetCommBreak(HANDLE fd);

static struct hook_symbol serial_syms[] = {
    {
        .name   = "ClearCommError",
        .patch  = my_ClearCommError,
    }, {
        .name   = "EscapeCommFunction",
        .patch  = my_EscapeCommFunction,
    }, {
        .name   = "GetCommMask",
        .patch  = my_GetCommMask,
    }, {
        .name   = "GetCommState",
        .patch  = my_GetCommState,
    }, {
        .name   = "GetCommTimeouts",
        .patch  = my_GetCommTimeouts,
    }, {
        .name   = "PurgeComm",
        .patch  = my_PurgeComm,
    }, {
        .name   = "SetCommMask",
        .patch  = my_SetCommMask,
    }, {
        .name   = "SetCommState",
        .patch  = my_SetCommState,
    }, {
        .name   = "SetCommTimeouts",
        .patch  = my_SetCommTimeouts,
    }, {
        .name   = "SetupComm",
        .patch  = my_SetupComm,
    }, {
        .name   = "SetCommBreak",
        .patch  = my_SetCommBreak,
    }, {
        .name   = "ClearCommBreak",
        .patch  = my_ClearCommBreak,
    },
};

static bool serial_hook_initted;

void serial_hook_init(void)
{
    if (serial_hook_initted) {
        return;
    }

    hook_table_apply(NULL, "kernel32.dll", serial_syms, _countof(serial_syms));
    serial_hook_initted = true;
}

static BOOL WINAPI my_ClearCommError(
        HANDLE fd,
        uint32_t *errors,
        COMSTAT *status)
{
    struct irp irp;
    SERIAL_STATUS llstatus;
    HRESULT hr;

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_GET_COMMSTATUS;
    irp.read.bytes = (uint8_t *) &llstatus;
    irp.read.nbytes = sizeof(llstatus);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    /* Here we just translate between two structures that carry essentially the
       same information, because Windows. */

    if (errors != NULL) {
        *errors = 0;

        if (llstatus.Errors & SERIAL_ERROR_QUEUEOVERRUN) {
            *errors |= CE_OVERRUN;
        }

        if (llstatus.Errors & SERIAL_ERROR_OVERRUN) {
            *errors |= CE_RXOVER;
        }

        if (llstatus.Errors & SERIAL_ERROR_BREAK) {
            *errors |= CE_BREAK;
        }

        if (llstatus.Errors & SERIAL_ERROR_PARITY) {
            *errors |= CE_RXPARITY;
        }

        if (llstatus.Errors & SERIAL_ERROR_FRAMING) {
            *errors |= CE_FRAME;
        }
    }

    if (status != NULL) {
        memset(status, 0, sizeof(*status));

        if (llstatus.HoldReasons & SERIAL_TX_WAITING_FOR_CTS) {
            status->fCtsHold = 1;
        }

        if (llstatus.HoldReasons & SERIAL_TX_WAITING_FOR_DSR) {
            status->fDsrHold = 1;
        }

        if (llstatus.HoldReasons & SERIAL_TX_WAITING_FOR_DCD) {
            status->fRlsdHold = 1;
        }

        if (llstatus.HoldReasons & SERIAL_TX_WAITING_FOR_XON) {
            status->fXoffHold = 1;
        }

        if (llstatus.HoldReasons & SERIAL_TX_WAITING_ON_BREAK) {
            /* hrm. No corresponding (documented field). */
        }

        if (llstatus.HoldReasons & SERIAL_TX_WAITING_XOFF_SENT) {
            status->fXoffSent = 1;
        }

        if (llstatus.EofReceived) {
            status->fEof = 1;
        }

        if (llstatus.WaitForImmediate) {
            status->fTxim = 1;
        }

        status->cbInQue = llstatus.AmountInInQueue;
        status->cbOutQue = llstatus.AmountInOutQueue;
    }

    return TRUE;
}

static BOOL WINAPI my_EscapeCommFunction(HANDLE fd, uint32_t cmd)
{
    struct irp irp;
    uint32_t ioctl;
    HRESULT hr;

    switch (cmd) {
    case CLRBREAK:  ioctl = IOCTL_SERIAL_SET_BREAK_OFF; break;
    case CLRDTR:    ioctl = IOCTL_SERIAL_CLR_DTR; break;
    case CLRRTS:    ioctl = IOCTL_SERIAL_CLR_RTS; break;
    case SETBREAK:  ioctl = IOCTL_SERIAL_SET_BREAK_ON; break;
    case SETDTR:    ioctl = IOCTL_SERIAL_SET_DTR; break;
    case SETRTS:    ioctl = IOCTL_SERIAL_SET_RTS; break;
    case SETXOFF:   ioctl = IOCTL_SERIAL_SET_XOFF; break;
    case SETXON:    ioctl = IOCTL_SERIAL_SET_XON; break;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = ioctl;

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    return TRUE;
}

static BOOL WINAPI my_GetCommMask(HANDLE fd, uint32_t *out)
{
    struct irp irp;
    uint32_t mask;
    HRESULT hr;

    if (out == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_GET_WAIT_MASK;
    irp.read.bytes = (uint8_t *) &mask;
    irp.read.nbytes = sizeof(mask);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI my_GetCommState(HANDLE fd, DCB *dcb)
{
    struct irp irp;
    SERIAL_BAUD_RATE baud;
    SERIAL_CHARS chars;
    SERIAL_HANDFLOW handflow;
    SERIAL_LINE_CONTROL line;
    HRESULT hr;

    /* Validate params. Despite what MSDN has to say on the matter, the
       DCBlength field is not validated (and is indeed overwritten) by the real
       implementation of this function. */

    if (dcb == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    /* Issue ioctls */

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_GET_BAUD_RATE;
    irp.read.bytes = (uint8_t *) &baud;
    irp.read.nbytes = sizeof(baud);
    memset(&baud, 0, sizeof(baud));

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_GET_HANDFLOW;
    irp.read.bytes = (uint8_t *) &handflow;
    irp.read.nbytes = sizeof(handflow);
    memset(&handflow, 0, sizeof(handflow));

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_GET_LINE_CONTROL;
    irp.read.bytes = (uint8_t *) &line;
    irp.read.nbytes = sizeof(line);
    memset(&line, 0, sizeof(line));

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_GET_CHARS;
    irp.read.bytes = (uint8_t *) &chars;
    irp.read.nbytes = sizeof(chars);
    memset(&chars, 0, sizeof(chars));

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    /* Populate output struct */

    memset(dcb, 0, sizeof(*dcb));
    dcb->DCBlength = sizeof(*dcb);
    dcb->fBinary = 1;
    dcb->BaudRate = baud.BaudRate;
    /* Populate fParity somehow? */

    if (handflow.ControlHandShake & SERIAL_CTS_HANDSHAKE) {
        dcb->fOutxCtsFlow = 1;
    }

    if (handflow.ControlHandShake & SERIAL_DSR_HANDSHAKE) {
        dcb->fOutxDsrFlow = 1;
    }

    if (handflow.ControlHandShake & SERIAL_DTR_CONTROL) {
        dcb->fDtrControl = DTR_CONTROL_ENABLE;
    }

    if (handflow.ControlHandShake & SERIAL_DTR_HANDSHAKE) {
        dcb->fDtrControl = DTR_CONTROL_HANDSHAKE;
    }

    if (handflow.ControlHandShake & SERIAL_DSR_SENSITIVITY) {
        dcb->fDsrSensitivity = 1;
    }

    if (handflow.ControlHandShake & SERIAL_XOFF_CONTINUE) {
        dcb->fTXContinueOnXoff = 1;
    }

    if (handflow.ControlHandShake & SERIAL_RTS_CONTROL) {
        dcb->fRtsControl = RTS_CONTROL_ENABLE;
    }

    if (handflow.ControlHandShake & SERIAL_RTS_HANDSHAKE) {
        dcb->fRtsControl = RTS_CONTROL_HANDSHAKE;
    }

    if (handflow.ControlHandShake & SERIAL_ERROR_ABORT) {
        dcb->fAbortOnError = 1;
    }

    if (handflow.ControlHandShake & SERIAL_ERROR_CHAR) {
        dcb->fErrorChar = 1;
    }

    if (handflow.ControlHandShake & SERIAL_NULL_STRIPPING) {
        dcb->fNull = 1;
    }

    dcb->XonLim = handflow.XonLimit;
    dcb->XoffLim = handflow.XoffLimit;
    dcb->ByteSize = line.WordLength;
    dcb->Parity = line.Parity;
    dcb->StopBits = line.StopBits;
    dcb->XonChar = chars.XonChar;
    dcb->XoffChar = chars.XoffChar;
    dcb->ErrorChar = chars.ErrorChar;
    dcb->EofChar = chars.EofChar;
    dcb->EvtChar = chars.EventChar;

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI my_GetCommTimeouts(HANDLE fd, COMMTIMEOUTS *dest)
{
    struct irp irp;
    SERIAL_TIMEOUTS src;
    HRESULT hr;

    if (dest == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_GET_TIMEOUTS;
    irp.read.bytes = (uint8_t *) &src;
    irp.read.nbytes = sizeof(src);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    dest->ReadIntervalTimeout           = src.ReadIntervalTimeout;
    dest->ReadTotalTimeoutMultiplier    = src.ReadTotalTimeoutMultiplier;
    dest->ReadTotalTimeoutConstant      = src.ReadTotalTimeoutConstant;
    dest->WriteTotalTimeoutMultiplier   = src.WriteTotalTimeoutMultiplier;
    dest->WriteTotalTimeoutConstant     = src.WriteTotalTimeoutConstant;

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI my_PurgeComm(HANDLE fd, uint32_t flags)
{
    struct irp irp;
    HRESULT hr;

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_PURGE;
    irp.write.bytes = (uint8_t *) &flags;
    irp.write.nbytes = sizeof(flags);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI my_SetCommMask(HANDLE fd, uint32_t mask)
{
    struct irp irp;
    HRESULT hr;

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_SET_WAIT_MASK;
    irp.write.bytes = (uint8_t *) &mask;
    irp.write.nbytes = sizeof(mask);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI my_SetCommState(HANDLE fd, const DCB *dcb)
{
    struct irp irp;
    SERIAL_BAUD_RATE baud;
    SERIAL_CHARS chars;
    SERIAL_HANDFLOW handflow;
    SERIAL_LINE_CONTROL line;
    HRESULT hr;

    if (dcb == NULL || dcb->DCBlength != sizeof(*dcb)) {
        /* This struct has evolved in the past, but those were the Windows 95
           days. So we only support the latest size of this struct. */
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    memset(&baud, 0, sizeof(baud));
    baud.BaudRate = dcb->BaudRate;

    memset(&handflow, 0, sizeof(handflow));

    if (dcb->fOutxCtsFlow) {
        handflow.ControlHandShake |= SERIAL_CTS_HANDSHAKE;
    }

    if (dcb->fOutxDsrFlow) {
        handflow.ControlHandShake |= SERIAL_DSR_HANDSHAKE;
    }

    switch (dcb->fDtrControl) {
    case DTR_CONTROL_DISABLE:
        break;

    case DTR_CONTROL_ENABLE:
        handflow.ControlHandShake |= SERIAL_DTR_CONTROL;

        break;

    case DTR_CONTROL_HANDSHAKE:
        handflow.ControlHandShake |= SERIAL_DTR_HANDSHAKE;

        break;

    default:
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (dcb->fDsrSensitivity) {
        handflow.ControlHandShake |= SERIAL_DSR_SENSITIVITY;
    }

    if (dcb->fTXContinueOnXoff) {
        handflow.ControlHandShake |= SERIAL_XOFF_CONTINUE;
    }

    switch (dcb->fRtsControl) {
    case RTS_CONTROL_DISABLE:
        break;

    case RTS_CONTROL_ENABLE:
        handflow.ControlHandShake |= SERIAL_RTS_CONTROL;

        break;

    case RTS_CONTROL_HANDSHAKE:
        handflow.ControlHandShake |= SERIAL_RTS_HANDSHAKE;

        break;

    default:
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    memset(&line, 0, sizeof(line));
    line.WordLength = dcb->ByteSize;
    line.Parity = dcb->Parity;
    line.StopBits = dcb->StopBits;

    memset(&chars, 0, sizeof(chars));
    chars.XonChar = dcb->XonChar;
    chars.XoffChar = dcb->XoffChar;
    chars.ErrorChar = dcb->ErrorChar;
    chars.EofChar = dcb->EofChar;
    chars.EventChar = dcb->EvtChar;

    /* Parameters populated and validated, commit new settings */

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_SET_BAUD_RATE;
    irp.write.bytes = (uint8_t *) &baud;
    irp.write.nbytes = sizeof(baud);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_SET_HANDFLOW;
    irp.write.bytes = (uint8_t *) &handflow;
    irp.write.nbytes = sizeof(handflow);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_SET_LINE_CONTROL;
    irp.write.bytes = (uint8_t *) &line;
    irp.write.nbytes = sizeof(line);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_SET_CHARS;
    irp.write.bytes = (uint8_t *) &chars;
    irp.write.nbytes = sizeof(chars);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI my_SetCommTimeouts(HANDLE fd, COMMTIMEOUTS *src)
{
    struct irp irp;
    SERIAL_TIMEOUTS dest;
    HRESULT hr;

    if (src == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    dest.ReadIntervalTimeout            = src->ReadIntervalTimeout;
    dest.ReadTotalTimeoutMultiplier     = src->ReadTotalTimeoutMultiplier;
    dest.ReadTotalTimeoutConstant       = src->ReadTotalTimeoutConstant;
    dest.WriteTotalTimeoutMultiplier    = src->WriteTotalTimeoutMultiplier;
    dest.WriteTotalTimeoutConstant      = src->WriteTotalTimeoutConstant;

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_SET_TIMEOUTS;
    irp.write.bytes = (uint8_t *) &dest;
    irp.write.nbytes = sizeof(dest);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI my_SetupComm(HANDLE fd, uint32_t in_q, uint32_t out_q)
{
    struct irp irp;
    SERIAL_QUEUE_SIZE qs;
    HRESULT hr;

    qs.InSize = in_q;
    qs.OutSize = out_q;

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_SET_QUEUE_SIZE;
    irp.write.bytes = (uint8_t *) &qs;
    irp.write.nbytes = sizeof(qs);

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI my_SetCommBreak(HANDLE fd)
{
    struct irp irp;
    HRESULT hr;

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_SET_BREAK_ON;

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI my_ClearCommBreak(HANDLE fd)
{
    struct irp irp;
    HRESULT hr;

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = fd;
    irp.ioctl = IOCTL_SERIAL_SET_BREAK_OFF;

    hr = iohook_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}
