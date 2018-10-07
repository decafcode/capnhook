/* Win32 user-mode API */
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <unknwn.h>

/* Win32 kernel-mode definitions */
#include <ntdef.h>
#include <devioctl.h>
#include <ntddser.h>

/* ANSI C */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
