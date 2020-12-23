#include <stdio.h>
#include <stdarg.h>

#include "hyperion.h"

BOOL display_verbose = FALSE;

void verbose(const char *format, ...)
{
    va_list args;
    if (!display_verbose)
        return;

    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
