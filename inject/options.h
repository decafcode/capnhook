#pragma once

#include <windows.h>

#include <stdbool.h>
#include <stdio.h>

struct options {
    bool help;
    bool wait;
    bool debug;
    bool debug_pause;
    int dll_pos;
    int orig_argc;
    char **orig_argv;
    int target_argc;
    char **target_argv;
};

void options_help(FILE *f);
HRESULT options_init(struct options *opt, int argc, char **argv);
HRESULT options_target_cmdline(const struct options *opt, char **str);
HRESULT options_next_dll(struct options *opt, const char **dll);
