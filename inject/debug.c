#include <windows.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static HRESULT debug_wstr(HANDLE process, const OUTPUT_DEBUG_STRING_INFO *odsi);
static bool debug_str(HANDLE process, const OUTPUT_DEBUG_STRING_INFO *odsi);

HRESULT debug_main(HANDLE process, uint32_t pid)
{
    DEBUG_EVENT ev;
    DWORD status;
    HRESULT hr;
    BOOL ok;

    for (;;) {
        ok = WaitForDebugEvent(&ev, INFINITE);

        if (!ok) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            fprintf(stderr, "WaitForDebugEvent failed: %x\n", (int) hr);

            return hr;
        }

        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            CloseHandle(ev.u.CreateProcessInfo.hFile);

            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            if (ev.dwProcessId == pid) {
                return S_OK;
            }

            break;

        case LOAD_DLL_DEBUG_EVENT:
            CloseHandle(ev.u.LoadDll.hFile);

            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            if (ev.dwProcessId == pid) {
                if (ev.u.DebugString.fUnicode) {
                    hr = debug_wstr(process, &ev.u.DebugString);
                } else {
                    hr = debug_str(process, &ev.u.DebugString);
                }

                if (FAILED(hr)) {
                    return hr;
                }
            }

            break;
        }

        if (ev.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT) {
            status = DBG_CONTINUE;
        } else {
            status = DBG_EXCEPTION_NOT_HANDLED;
        }

        ok = ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);

        if (!ok) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            fprintf(stderr, "ContinueDebugEvent failed: %x\n", (int) hr);

            return hr;
        }
    }
}

static HRESULT debug_wstr(HANDLE process, const OUTPUT_DEBUG_STRING_INFO *odsi)
{
    char *str;
    wchar_t *wstr;
    int nbytes_w;
    int nbytes_a;
    int result;
    HRESULT hr;
    BOOL ok;

    str = NULL;
    nbytes_w = odsi->nDebugStringLength * sizeof(wchar_t);
    wstr = malloc(nbytes_w);

    if (wstr == NULL) {
        hr = E_OUTOFMEMORY;

        goto end;
    }

    ok = ReadProcessMemory(
            process,
            odsi->lpDebugStringData,
            wstr,
            nbytes_w,
            NULL);

    if (!ok) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr,
                "%s: ReadProcessMemory failed: %x\n",
                __func__,
                (int) hr);

        goto end;
    }

    nbytes_a = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
    str = malloc(nbytes_a);

    if (str == NULL) {
        hr = E_OUTOFMEMORY;

        goto end;
    }

    result = WideCharToMultiByte(CP_ACP, 0, wstr, -1, str, nbytes_a, NULL,NULL);

    if (result == 0) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "WideCharToMultiByte failed: %x\n", (int) hr);

        goto end;
    }

    fputs(str, stdout);

    hr = S_OK;

end:
    free(str);
    free(wstr);

    return hr;
}

static bool debug_str(HANDLE process, const OUTPUT_DEBUG_STRING_INFO *odsi)
{
    char *str;
    HRESULT hr;
    BOOL ok;

    str = malloc(odsi->nDebugStringLength);

    if (str == NULL) {
        hr = E_OUTOFMEMORY;

        goto end;
    }

    ok = ReadProcessMemory(
            process,
            odsi->lpDebugStringData,
            str,
            odsi->nDebugStringLength,
            NULL);

    if (!ok) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "%s: ReadProcessMemory failed: %x", __func__, (int) hr);

        goto end;
    }

    fputs(str, stdout);

    hr = S_OK;

end:
    free(str);

    return hr;
}
