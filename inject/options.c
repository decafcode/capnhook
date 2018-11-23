#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "inject/options.h"

void options_help(FILE *f)
{
    assert(f != NULL);

    fputs(  "Usage: inject [options] program args...\n"
            "All options must precede the program name.\n"
            "\n"
            "The following options are understood:\n"
            "\n"
            "-h\tPrint this message.\n"
            "\n"
            "-d\tAttach to target as a debugger and print debug messages.\n"
            "\n"
            "-p\tPause the target until a debugger attaches to it.\n"
            "  \tCannot be used with -d.\n"
            "\n"
            "-w\tWait for target to terminate.\n"
            "  \tCannot be used with -d.\n"
            "\n"
            "-k dll\tInject the named DLL into the target process.\n"
            "  \tCan be specified more than once.\n"
            "\n",
            f);
}

HRESULT options_init(struct options *opt, int argc, char **argv)
{
    int nconsumed;
    const char *arg;
    int i;

    assert(opt != NULL);

    memset(opt, 0, sizeof(*opt));
    nconsumed = 1;

    for (i = 1 ; i < argc && argv[i][0] == '-' ; i++) {
        arg = argv[i];
        nconsumed++;

        switch (arg[1]) {
        case 'h':
            opt->help = true;

            break;

        case 'd':
            if (opt->debug_pause || opt->wait) {
                return E_FAIL;
            }

            opt->debug = true;

            break;

        case 'p':
            if (opt->debug) {
                return E_FAIL;
            }

            opt->debug_pause = true;

            break;

        case 'w':
            if (opt->debug) {
                return E_FAIL;
            }

            opt->wait = true;

            break;

        case 'k':
            if (i + 1 >= argc) {
                return E_FAIL;
            }

            /* These get pulled by options_next_dll. Consume its argument as
               well though. */

            nconsumed++;
            i++;

            break;

        default:
            return E_FAIL;
        }
    }

    if (nconsumed == argc) {
        return E_FAIL;
    }

    opt->orig_argc = argc;
    opt->orig_argv = argv;
    opt->target_argc = argc - nconsumed;
    opt->target_argv = argv + nconsumed;
    opt->dll_pos = 1;

    return S_OK;
}

HRESULT options_target_cmdline(const struct options *opt, char **out)
{
    char *str;
    char *pos;
    size_t nchars;
    size_t len;
    int i;

    assert(opt != NULL);
    assert(out != NULL);

    *out = NULL;

    /* Measure string. Each element requires an opening quote, a closing quote
       and either a trailing space or a trailing NUL. */

    nchars = 3 * opt->target_argc;

    for (i = 0 ; i < opt->target_argc ; i++) {
        nchars += strlen(opt->target_argv[i]);
    }

    str = malloc(nchars);

    if (str == NULL) {
        return E_OUTOFMEMORY;
    }

    /* Construct string. This doesn't escape quotes within individual args yet
       but ugh I'll fix that later if it really becomes necessary, it's a pain
       to deal with. */

    for (i = 0, pos = str ; i < opt->target_argc ; i++) {
        len = strlen(opt->target_argv[i]);

        *pos++ = '"';
        memcpy(pos, opt->target_argv[i], len);
        pos += len;
        *pos++ = '"';

        if (i + 1 < opt->target_argc) {
            *pos++ = ' ';
        } else {
            *pos++ = '\0';
        }
    }

    *out = str;

    return S_OK;
}

HRESULT options_next_dll(struct options *opt, const char **out)
{
    const char *arg;

    assert(opt != NULL);
    assert(opt->orig_argv != NULL);
    assert(out != NULL);

    *out = NULL;

    while (opt->dll_pos < opt->orig_argc) {
        arg = opt->orig_argv[opt->dll_pos];

        if (arg[0] != '-') {
            break;
        }

        opt->dll_pos++;

        if (arg[1] == 'k' && opt->dll_pos < opt->orig_argc) {
            *out = opt->orig_argv[opt->dll_pos++];

            return S_OK;
        }
    }

    return S_FALSE;
}

