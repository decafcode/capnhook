#include <windows.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "inject/debug.h"
#include "inject/options.h"

static HRESULT inject_dll(HANDLE process, const char *dll_name);
static HRESULT inject_pause(HANDLE process);
static HRESULT inject_resume(HANDLE thread);

int main(int argc, char **argv)
{
    struct options opt;
    char *cmdline;
    const char *hook_dll;
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    HRESULT hr;
    BOOL ok;

    hr = options_init(&opt, argc, argv);

    if (FAILED(hr) || opt.help) {
        options_help(stderr);

        return EXIT_FAILURE;
    }

    cmdline = NULL;
    hr = options_target_cmdline(&opt, &cmdline);

    if (FAILED(hr)) {
        goto end;
    }

    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    ok = CreateProcessA(
            NULL,
            cmdline,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi);

    if (!ok) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "Failed to launch executable: %x\n", (int) hr);

        goto end;
    }

    while (options_next_dll(&opt, &hook_dll) == S_OK) {
        hr = inject_dll(pi.hProcess, hook_dll);

        if (FAILED(hr)) {
            goto end;
        }
    }

    if (opt.debug_pause) {
        hr = inject_pause(pi.hProcess);

        if (FAILED(hr)) {
            goto end;
        }
    }

    if (opt.debug) {
        ok = DebugActiveProcess(pi.dwProcessId);

        if (!ok) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            fprintf(stderr, "DebugActiveProcess failed: %x\n", (int) hr);

            goto end;
        }
    }

    hr = inject_resume(pi.hThread);

    if (FAILED(hr)) {
        goto end;
    }

    if (opt.debug) {
        hr = debug_main(pi.hProcess, pi.dwProcessId);
    }

    if (opt.wait) {
        WaitForSingleObject(pi.hProcess, INFINITE);
    }

end:
    if (pi.hProcess != NULL) {
        if (FAILED(hr)) {
            TerminateProcess(pi.hProcess, EXIT_FAILURE);
        }

        CloseHandle(pi.hProcess);
    }

    if (pi.hThread != NULL) {
        CloseHandle(pi.hThread);
    }

    free(cmdline);

    return FAILED(hr) ? EXIT_FAILURE : EXIT_SUCCESS;
}

static HRESULT inject_dll(HANDLE process, const char *dll_name)
{
    size_t nchars;
    void *remote_addr;
    HANDLE remote_thread;
    DWORD found;
    HRESULT hr;
    BOOL ok;

    remote_addr = NULL;
    remote_thread = NULL;

    found = SearchPathA(NULL, dll_name, NULL, 0, NULL, NULL);

    if (found == 0) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "%s: Hook DLL not found: %x\n", dll_name, (int) hr);

        goto end;
    }

    nchars = strlen(dll_name);

    remote_addr = VirtualAllocEx(
            process,
            NULL,
            nchars + 1,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);

    if (remote_addr == NULL) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "VirtualAllocEx failed: %x\n", (int) hr);

        goto end;
    }

    ok = WriteProcessMemory(
            process,
            remote_addr,
            dll_name,
            nchars + 1,
            NULL);

    if (!ok) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "WriteProcessMemory failed: %x\n", (int) hr);

        goto end;
    }

    remote_thread = CreateRemoteThread(
            process,
            NULL,
            0,
            (LPTHREAD_START_ROUTINE) LoadLibraryA,
            remote_addr,
            0,
            NULL);

    if (remote_thread == NULL) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "CreateRemoteThread failed: %x\n", (int) hr);

        goto end;
    }

    hr = S_OK;

end:
    if (remote_thread != NULL) {
        WaitForSingleObject(remote_thread, INFINITE);
        CloseHandle(remote_thread);
    }

    if (remote_addr != NULL) {
        ok = VirtualFreeEx(process, remote_addr, 0, MEM_RELEASE);

        if (!ok) {
            fprintf(stderr, "VirtualFreeEx failed\n");
        }
    }

    return hr;
}

static HRESULT inject_pause(HANDLE process)
{
    HRESULT hr;
    BOOL present;
    BOOL ok;

    printf("Waiting for debugger to attach.\n");

    do {
        Sleep(1000);
        ok = CheckRemoteDebuggerPresent(process, &present);

        if (!ok) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            fprintf(stderr, "CheckRemoteDebuggerPresent failed: %x\n", (int)hr);

            return hr;
        }
    } while (!present);

    printf("Debugger attached, resuming\n");

    return S_OK;
}

static HRESULT inject_resume(HANDLE thread)
{
    DWORD result;
    HRESULT hr;

    result = ResumeThread(thread);

    if (result == -1) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "Failed to resume target thread: %x\n", (int) hr);

        return hr;
    }

    return S_OK;
}


