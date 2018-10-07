#pragma once

#include <windows.h>

#define hr_propagate_win32(hr, r) (hr_propagate_win32_(hr), r)

void hr_propagate_win32_(HRESULT hr);
