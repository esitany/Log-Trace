
#include <stdio.h>

#include "log_trace.h"

void usage(const char *file)
{
    printf("%s [Log file path]\n", file);
}

int main(int argc, char **argv)
{
    int  len = 0;
    char msg[128] = {"\0"};

    if (argc > 1) {
        ltInitailize(argv[1]);
        len = snprintf(msg, 128, "LT Debug Message");
        ltMsg( "TEST", LT_DEBUG, __FILE__, __LINE__, msg);
        ltDump("TEST", LT_DEBUG, __FILE__, __LINE__, msg, len, "LT Dump");

        len = snprintf(msg, 128, "LT Information Message");
        ltMsg( "TEST", LT_INFO, __FILE__, __LINE__, msg);
        ltDump("TEST", LT_INFO, __FILE__, __LINE__, msg, len, "LT Dump");

        len = snprintf(msg, 128, "LT Warnning Message");
        ltMsg( "TEST", LT_WARN, __FILE__, __LINE__, msg);
        ltDump("TEST", LT_WARN, __FILE__, __LINE__, msg, len, "LT Dump");

        len = snprintf(msg, 128, "LT Error Message");
        ltMsg( "TEST", LT_ERR, __FILE__, __LINE__, msg);
        ltDump("TEST", LT_ERR, __FILE__, __LINE__, msg, len, "LT Dump");

        len = snprintf(msg, 128, "LT Critical Message");
        ltMsg("TEST",  LT_CRITICAL, __FILE__, __LINE__, msg);
        ltDump("TEST", LT_CRITICAL, __FILE__, __LINE__, msg, len, "LT Dump");

        ltDestroy();
    }
    else {
        usage(argv[0]);
    }

    return 0;
}

