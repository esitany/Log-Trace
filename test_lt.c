
#include <stdio.h>

#include "log_trace.h"

void usage(const char *file)
{
    printf("%s [Log file path]\n", file);
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        ltInitailize(argv[1]);
        ltMsg("TEST", LT_DEBUG, __FILE__, __LINE__, "LT Debug MESSAGE");
        ltMsg("TEST", LT_WARN,  __FILE__, __LINE__, "LT Warnning MESSAGE");
        ltMsg("TEST", LT_INFO,  __FILE__, __LINE__, "LT Information MESSAGE");
        ltMsg("TEST", LT_ERR,   __FILE__, __LINE__, "LT Error MESSAGE");

        ltDestroy();
    }
    else {
        usage(argv[0]);
    }

    return 0;
}

