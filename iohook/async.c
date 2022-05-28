#include <windows.h>

#include <stdint.h>

#include "iohook/async.h"

BOOL iohook_overlapped_result(
        uint32_t *syncout,
        OVERLAPPED *ovl,
        uint32_t value)
{
    if (ovl != NULL) {
        ovl->Internal = STATUS_SUCCESS;
        ovl->InternalHigh = value;

        if (ovl->hEvent != NULL) {
            SetEvent(ovl->hEvent);
        }
    }

    if (syncout != NULL) {
        *syncout = value;
        SetLastError(ERROR_SUCCESS);

        return TRUE;
    } else {
        SetLastError(ERROR_IO_PENDING);

        return FALSE;
    }
}
