#define WIN32_NO_STATUS
/* See precompiled.h for more information */
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>

#include <winnt.h>
#include <devioctl.h>
#include <ntstatus.h>

#include "hook/hr.h"
#include "hook/table.h"

#include "iohook/async.h"
#include "iohook/chain.h"
#include "iohook/file.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

/* API hooks. We take some liberties with function signatures here (e.g.
   stdint.h types instead of DWORD and LARGE_INTEGER et al). */

static BOOL WINAPI iohook_CloseHandle(HANDLE fd);

static HANDLE WINAPI iohook_CreateFileW(
        const wchar_t *lpFileName,
        uint32_t dwDesiredAccess,
        uint32_t dwShareMode,
        SECURITY_ATTRIBUTES *lpSecurityAttributes,
        uint32_t dwCreationDisposition,
        uint32_t dwFlagsAndAttributes,
        HANDLE hTemplateFile);

static HANDLE WINAPI iohook_CreateFileA(
        const char *lpFileName,
        uint32_t dwDesiredAccess,
        uint32_t dwShareMode,
        SECURITY_ATTRIBUTES *lpSecurityAttributes,
        uint32_t dwCreationDisposition,
        uint32_t dwFlagsAndAttributes,
        HANDLE hTemplateFile);

static BOOL WINAPI iohook_ReadFile(
        HANDLE hFile,
        void *lpBuffer,
        uint32_t nNumberOfBytesToRead,
        uint32_t *lpNumberOfBytesRead,
        OVERLAPPED *lpOverlapped);

static BOOL WINAPI iohook_WriteFile(
        HANDLE hFile,
        const void *lpBuffer,
        uint32_t nNumberOfBytesToWrite,
        uint32_t *lpNumberOfBytesWritten,
        OVERLAPPED *lpOverlapped);

static DWORD WINAPI iohook_SetFilePointer(
        HANDLE hFile,
        int32_t lDistanceToMove,
        int32_t *lpDistanceToMoveHigh,
        uint32_t dwMoveMethod);

static BOOL WINAPI iohook_SetFilePointerEx(
        HANDLE hFile,
        int64_t liDistanceToMove,
        uint64_t *lpNewFilePointer,
        uint32_t dwMoveMethod);

static BOOL WINAPI iohook_FlushFileBuffers(HANDLE hFile);

static BOOL WINAPI iohook_DeviceIoControl(
        HANDLE hFile,
        uint32_t dwIoControlCode,
        void *lpInBuffer,
        uint32_t nInBufferSize,
        void *lpOutBuffer,
        uint32_t nOutBufferSize,
        uint32_t *lpBytesReturned,
        OVERLAPPED *lpOverlapped);

/* Links */

static BOOL (WINAPI *next_CloseHandle)(HANDLE fd);

static HANDLE (WINAPI *next_CreateFileA)(
        const char *lpFileName,
        uint32_t dwDesiredAccess,
        uint32_t dwShareMode,
        SECURITY_ATTRIBUTES *lpSecurityAttributes,
        uint32_t dwCreationDisposition,
        uint32_t dwFlagsAndAttributes,
        HANDLE hTemplateFile);

static HANDLE (WINAPI *next_CreateFileW)(
        const wchar_t *filename,
        uint32_t access,
        uint32_t share,
        SECURITY_ATTRIBUTES *sa,
        uint32_t creation,
        uint32_t flags,
        HANDLE tmpl);

static BOOL (WINAPI *next_DeviceIoControl)(
        HANDLE fd,
        uint32_t code,
        void *in_bytes,
        uint32_t in_nbytes,
        void *out_bytes,
        uint32_t out_nbytes,
        uint32_t *out_returned,
        OVERLAPPED *ovl);

static BOOL (WINAPI *next_ReadFile)(
        HANDLE fd,
        void *buf,
        uint32_t nbytes,
        uint32_t *nread,
        OVERLAPPED *ovl);

static BOOL (WINAPI *next_WriteFile)(
        HANDLE fd,
        const void *buf,
        uint32_t nbytes,
        uint32_t *nwrit,
        OVERLAPPED *ovl);

static DWORD (WINAPI *next_SetFilePointer)(
        HANDLE hFile,
        int32_t lDistanceToMove,
        int32_t *lpDistanceToMoveHigh,
        uint32_t dwMoveMethod);

static BOOL (WINAPI *next_SetFilePointerEx)(
        HANDLE hFile,
        int64_t liDistanceToMove,
        uint64_t *lpNewFilePointer,
        uint32_t dwMoveMethod);

static BOOL (WINAPI *next_FlushFileBuffers)(HANDLE fd);

/* Hook symbol table */

static const struct hook_symbol iohook_kernel32_syms[] = {
    {
        .name   = "CloseHandle",
        .patch  = iohook_CloseHandle,
        .link   = (void *) &next_CloseHandle,
    }, {
        .name   = "CreateFileA",
        .patch  = iohook_CreateFileA,
        .link   = (void *) &next_CreateFileA,
    }, {
        .name   = "CreateFileW",
        .patch  = iohook_CreateFileW,
        .link   = (void *) &next_CreateFileW,
    }, {
        .name   = "DeviceIoControl",
        .patch  = iohook_DeviceIoControl,
        .link   = (void *) &next_DeviceIoControl,
    }, {
        .name   = "ReadFile",
        .patch  = iohook_ReadFile,
        .link   = (void *) &next_ReadFile,
    }, {
        .name   = "WriteFile",
        .patch  = iohook_WriteFile,
        .link   = (void *) &next_WriteFile,
    }, {
        .name   = "SetFilePointer",
        .patch  = iohook_SetFilePointer,
        .link   = (void *) &next_SetFilePointer,
    }, {
        .name   = "SetFilePointerEx",
        .patch  = iohook_SetFilePointerEx,
        .link   = (void *) &next_SetFilePointerEx,
    }, {
        .name   = "FlushFileBuffers",
        .patch  = iohook_FlushFileBuffers,
        .link   = (void *) &next_FlushFileBuffers,
    },
};

void iohook_file_hook_apis(void)
{
    HMODULE kernel32;

    /* Splice iohook into IAT entries referencing Win32 I/O APIs */

    hook_table_apply(
            NULL,
            "kernel32.dll",
            iohook_kernel32_syms,
            _countof(iohook_kernel32_syms));

    /* Here be dragons:

       The hook table mechanism will populate our next_ function pointers with
       the prior values of these IAT entries, and we invoke these next_
       function pointers to propagate IO requests onwards to the OS (or to
       whoever hooked everybody's IATs before us). We don't statically import
       these functions using the compiler because those static imports would
       also be realized as IAT entries somewhere, so we'd overwrite our own
       imports for the Win32 file I/O APIs and send ourselves into an infinite
       recursion.

       That being said, not all pass-through operations necessarily end up
       leaving through the same function that they entered through, owing to
       the existence of multiple and possibly-obsolete ways of doing various
       I/O things through the Win32 API. For instance, a call to CreateFileA
       intercepted by iohook will emerge as a call to CreateFileW. Similarly,
       a call to the clunky SetFilePointer API will emerge as a call to the
       safer and simpler SetFilePointerEx. This presents a problem if the
       desired API exit path isn't actually imported through an IAT that we
       touch with hook_table_apply. In this edge case, we have to explicitly
       call GetProcAddress to ensure that these function pointers are populated.

       Oh, and as with all other uses of hook_table_apply(), subtle problems
       may arise if a function is referenced from multiple IAT entries across
       the process and those IAT entries somehow end up not all pointing to the
       same destination. */

    kernel32 = GetModuleHandleW(L"kernel32.dll");

    if (next_CreateFileW == NULL) {
        next_CreateFileW = (void *) GetProcAddress(
                kernel32,
                "CreateFileW");
    }

    if (next_SetFilePointerEx == NULL) {
        next_SetFilePointerEx = (void *) GetProcAddress(
                kernel32,
                "SetFilePointerEx");
    }
}

HRESULT iohook_file_open_nul_fd(HANDLE *out)
{
    HANDLE fd;

    assert(out != NULL);

    *out = NULL;

    fd = next_CreateFileW(
            L"NUL",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            NULL);

    if (fd == NULL) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    *out = fd;

    return S_OK;
}

HRESULT iohook_invoke_real_open(struct irp *irp)
{
    HANDLE fd;

    assert(irp != NULL);

    fd = next_CreateFileW(
            irp->open_filename,
            irp->open_access,
            irp->open_share,
            irp->open_sa,
            irp->open_creation,
            irp->open_flags,
            irp->open_tmpl);

    if (fd == INVALID_HANDLE_VALUE) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    irp->fd = fd;

    return S_OK;
}

HRESULT iohook_invoke_real_close(struct irp *irp)
{
    BOOL ok;

    assert(irp != NULL);

    ok = next_CloseHandle(irp->fd);

    if (!ok) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT iohook_invoke_real_read(struct irp *irp)
{
    uint32_t nread;
    BOOL ok;

    assert(irp != NULL);

    ok = next_ReadFile(
            irp->fd,
            &irp->read.bytes[irp->read.pos],
            irp->read.nbytes - irp->read.pos,
            &nread,
            irp->ovl);

    if (!ok) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    irp->read.pos += nread;

    return S_OK;
}

HRESULT iohook_invoke_real_write(struct irp *irp)
{
    uint32_t nwrit;
    BOOL ok;

    assert(irp != NULL);

    ok = next_WriteFile(
            irp->fd,
            &irp->write.bytes[irp->write.pos],
            irp->write.nbytes - irp->write.pos,
            &nwrit,
            irp->ovl);

    if (!ok) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    irp->write.pos += nwrit;

    return S_OK;
}

HRESULT iohook_invoke_real_seek(struct irp *irp)
{
    BOOL ok;

    assert(irp != NULL);

    ok = next_SetFilePointerEx(
            irp->fd,
            irp->seek_offset,
            &irp->seek_pos,
            irp->seek_origin);

    if (!ok) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT iohook_invoke_real_fsync(struct irp *irp)
{
    BOOL ok;

    assert(irp != NULL);

    ok = next_FlushFileBuffers(irp->fd);

    if (!ok) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT iohook_invoke_real_ioctl(struct irp *irp)
{
    uint32_t nread;
    BOOL ok;

    assert(irp != NULL);

    /* ioctl in/out params tend to be structs, so it probably does not make
       sense to concatenate a synthetic result with a pass-through result in
       the same way as one might do with read/write. */

    assert(irp->write.pos == 0);
    assert(irp->read.pos == 0);

    ok = next_DeviceIoControl(
            irp->fd,
            irp->ioctl,
            (void *) irp->write.bytes, // Cast off const
            irp->write.nbytes,
            irp->read.bytes,
            irp->read.nbytes,
            &nread,
            irp->ovl);

    /* Must be propagated even if there is an error, see
       iohook_DeviceIoControl. */

    irp->read.pos = nread;

    if (!ok) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

static HANDLE WINAPI iohook_CreateFileA(
        const char *lpFileName,
        uint32_t dwDesiredAccess,
        uint32_t dwShareMode,
        SECURITY_ATTRIBUTES *lpSecurityAttributes,
        uint32_t dwCreationDisposition,
        uint32_t dwFlagsAndAttributes,
        HANDLE hTemplateFile)
{
    wchar_t *wfilename;
    int nchars;
    int result;
    HANDLE fd;

    fd = INVALID_HANDLE_VALUE;
    wfilename = NULL;

    if (lpFileName == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);

        goto end;
    }

    nchars = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, NULL, 0);
    wfilename = malloc(nchars * sizeof(wchar_t));

    if (wfilename == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);

        goto end;
    }

    result = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wfilename, nchars);

    if (result == 0) {
        goto end;
    }

    fd = iohook_CreateFileW(
            wfilename,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes,
            hTemplateFile);

end:
    free(wfilename);

    return fd;
}

static HANDLE WINAPI iohook_CreateFileW(
        const wchar_t *lpFileName,
        uint32_t dwDesiredAccess,
        uint32_t dwShareMode,
        SECURITY_ATTRIBUTES *lpSecurityAttributes,
        uint32_t dwCreationDisposition,
        uint32_t dwFlagsAndAttributes,
        HANDLE hTemplateFile)
{
    struct irp irp;
    HRESULT hr;

    if (lpFileName == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return INVALID_HANDLE_VALUE;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_OPEN;
    irp.fd = INVALID_HANDLE_VALUE;
    irp.open_filename = lpFileName;
    irp.open_access = dwDesiredAccess;
    irp.open_share = dwShareMode;
    irp.open_sa = lpSecurityAttributes;
    irp.open_creation = dwCreationDisposition;
    irp.open_flags = dwFlagsAndAttributes;
    irp.open_tmpl = hTemplateFile;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, INVALID_HANDLE_VALUE);
    }

    SetLastError(ERROR_SUCCESS);

    return irp.fd;
}

static BOOL WINAPI iohook_CloseHandle(HANDLE hFile)
{
    struct irp irp;
    HRESULT hr;

    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_CLOSE;
    irp.fd = hFile;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    /* Don't call SetLastError on success! */

    return TRUE;
}

static BOOL WINAPI iohook_ReadFile(
        HANDLE hFile,
        void *lpBuffer,
        uint32_t nNumberOfBytesToRead,
        uint32_t *lpNumberOfBytesRead,
        OVERLAPPED *lpOverlapped)
{
    struct irp irp;
    HRESULT hr;

    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE || lpBuffer == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (lpOverlapped == NULL) {
        if (lpNumberOfBytesRead == NULL) {
            SetLastError(ERROR_INVALID_PARAMETER);

            return FALSE;
        }

        *lpNumberOfBytesRead = 0;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_READ;
    irp.fd = hFile;
    irp.ovl = lpOverlapped;
    irp.read.bytes = lpBuffer;
    irp.read.nbytes = nNumberOfBytesToRead;
    irp.read.pos = 0;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    assert(irp.read.pos <= irp.read.nbytes);

    return iohook_overlapped_result(
            lpNumberOfBytesRead,
            lpOverlapped,
            irp.read.pos);
}

static BOOL WINAPI iohook_WriteFile(
        HANDLE hFile,
        const void *lpBuffer,
        uint32_t nNumberOfBytesToWrite,
        uint32_t *lpNumberOfBytesWritten,
        OVERLAPPED *lpOverlapped)
{
    struct irp irp;
    HRESULT hr;

    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE || lpBuffer == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (lpOverlapped == NULL) {
        if (lpNumberOfBytesWritten == NULL) {
            SetLastError(ERROR_INVALID_PARAMETER);

            return FALSE;
        }

        *lpNumberOfBytesWritten = 0;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_WRITE;
    irp.fd = hFile;
    irp.ovl = lpOverlapped;
    irp.write.bytes = lpBuffer;
    irp.write.nbytes = nNumberOfBytesToWrite;
    irp.write.pos = 0;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    assert(irp.write.pos <= irp.write.nbytes);

    return iohook_overlapped_result(
            lpNumberOfBytesWritten,
            lpOverlapped,
            irp.write.pos);
}

static DWORD WINAPI iohook_SetFilePointer(
        HANDLE hFile,
        int32_t lDistanceToMove,
        int32_t *lpDistanceToMoveHigh,
        uint32_t dwMoveMethod)
{
    struct irp irp;
    HRESULT hr;

    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return INVALID_SET_FILE_POINTER;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_SEEK;
    irp.fd = hFile;
    irp.seek_origin = dwMoveMethod;

    /* This is a clumsy API. In 32-bit mode lDistanceToMove is a signed 32-bit
       int, but in 64-bit mode it is a 32-bit UNsigned int. Care must be taken
       with sign-extension vs zero-extension here. */

    if (lpDistanceToMoveHigh != NULL) {
        irp.seek_offset = ((( int64_t) *lpDistanceToMoveHigh) << 32) |
                           ((uint64_t) lDistanceToMove      )        ;
    } else {
        irp.seek_offset =   ( int64_t) lDistanceToMove;
    }

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, INVALID_SET_FILE_POINTER);
    }

    SetLastError(ERROR_SUCCESS);

    if (lpDistanceToMoveHigh != NULL) {
        *lpDistanceToMoveHigh = irp.seek_pos >> 32;
    }

    return (DWORD) irp.seek_pos;
}

static BOOL WINAPI iohook_SetFilePointerEx(
        HANDLE hFile,
        int64_t liDistanceToMove,
        uint64_t *lpNewFilePointer,
        uint32_t dwMoveMethod)
{
    struct irp irp;
    HRESULT hr;

    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    /* Much nicer than SetFilePointer */

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_SEEK;
    irp.fd = hFile;
    irp.seek_offset = liDistanceToMove;
    irp.seek_origin = dwMoveMethod;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    if (lpNewFilePointer != NULL) {
        *lpNewFilePointer = irp.seek_pos;
    }

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI iohook_FlushFileBuffers(HANDLE hFile)
{
    struct irp irp;
    HRESULT hr;

    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_FSYNC;
    irp.fd = hFile;

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        return hr_propagate_win32(hr, FALSE);
    }

    SetLastError(ERROR_SUCCESS);

    return TRUE;
}

static BOOL WINAPI iohook_DeviceIoControl(
        HANDLE hFile,
        uint32_t dwIoControlCode,
        void *lpInBuffer,
        uint32_t nInBufferSize,
        void *lpOutBuffer,
        uint32_t nOutBufferSize,
        uint32_t *lpBytesReturned,
        OVERLAPPED *lpOverlapped)
{
    struct irp irp;
    HRESULT hr;

    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_PARAMETER);

        return FALSE;
    }

    if (lpOverlapped == NULL) {
        if (lpBytesReturned == NULL) {
            SetLastError(ERROR_INVALID_PARAMETER);

            return FALSE;
        }

        *lpBytesReturned = 0;
    }

    memset(&irp, 0, sizeof(irp));
    irp.op = IRP_OP_IOCTL;
    irp.fd = hFile;
    irp.ovl = lpOverlapped;
    irp.ioctl = dwIoControlCode;

    if (lpInBuffer != NULL) {
        irp.write.bytes = lpInBuffer;
        irp.write.nbytes = nInBufferSize;
    }

    if (lpOutBuffer != NULL) {
        irp.read.bytes = lpOutBuffer;
        irp.read.nbytes = nOutBufferSize;
    }

    hr = iohook_chain_invoke_next(&irp);

    if (FAILED(hr)) {
        /* Special case: ERROR_MORE_DATA requires this out parameter to be
           propagated, per MSDN. All ioctls in the entire process that go via
           the win32 API (as opposed to the NTDLL API) get redirected through
           iohook, and the Windows XP version of DirectSound is known to rely
           on this behavior. */

        if (lpBytesReturned != NULL) {
            *lpBytesReturned = (DWORD) irp.read.pos;
        }

        return hr_propagate_win32(hr, FALSE);
    }

    return iohook_overlapped_result(
            lpBytesReturned,
            lpOverlapped,
            irp.read.pos);
}
