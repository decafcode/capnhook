/*
    Making NTSTATUS available is slightly awkward. See:
    https://kirkshoop.github.io/2011/09/20/ntstatus.html
*/

/* Win32 user-mode API */
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winsock2.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <unknwn.h>

/* Win32 kernel-mode definitions */
#ifdef __GNUC__
/* MinGW needs to include this for PHYSICAL_ADDRESS to be defined.
   The MS SDK throws a bunch of duplicate symbol errors instead. */
#include <ntdef.h>
#else
#include <winnt.h>
#endif
#include <devioctl.h>
#include <ntddser.h>
#include <ntstatus.h>

/* ANSI C */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
