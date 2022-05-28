#pragma once

#include <windows.h>

#include <stdint.h>

BOOL iohook_overlapped_result(
        uint32_t *syncout,
        OVERLAPPED *ovl,
        uint32_t value);
