/**
* @file log_trace.h
* @brief This file declares control Log and Trace
* @author yikim
* @version 1.0
* @date 2021-07-23
*/

#ifndef _LOG_AND_TRACE_HEADER
#define _LOG_AND_TRACE_HEADER

#include <stdint.h>
#include <time.h>

#include "log_trace_color.h"

typedef enum ENUM_LT_TYPE {
    LT_MSG     = 0,  // Log Message
    LT_DUMP    ,     // Log Hex dump
    LT_UNKNOWN
} enLTType;

typedef enum ENUM_LT_LEVEL {
    LT_CRITICAL = 0,  // Log level Critical
    LT_ERR      ,     // Log level Error
    LT_WARN     ,     // Log Level Warning
    LT_INFO     ,     // Log Level Information
    LT_DEBUG          // Log level Debug
} enLTLevel;

#define LT_MAX_SIZE_DUMP  0x000FFFF // 64KB, 65535
#define LT_MAX_SIZE_MSG   0x0000400 // 1KB, 1024
//  #define LT_MAX_SIZE_FILE  0x0400000 // 4MB
#define LT_MAX_SIZE_FILE  0x0800000 // 8MB
#define LT_READ_SIZE      0x0008000 // 32KB, 32768

#define LT_FILE_LENGTH    16


typedef struct __attribute__((packed)) STRUCT_LOG_TRACE_TIME {
    time_t   sec;
    uint32_t usec;
} stLTTime;

typedef struct __attribute__((packed)) STRUCT_LOG_TRACE_INFORMATION_CONFIG {
    uint32_t type   : 4;  //  0: 3, Log type
    uint32_t level  : 4;  //  4: 7, log level
    uint32_t reseve :10;
} stLTICfg;

typedef struct __attribute__((packed)) STRUCT_LOG_TRACE_INFORMATION_FILE {
    uint32_t line;                 // file line number
    char     name[LT_FILE_LENGTH]; // file name
} stLTIFile;

typedef struct __attribute__((packed)) STRUCT_LOG_TRACE_INFORMATION {
    stLTICfg  cfg;       // log config
    char      tag[8+4];  // log tag name(Maximum 8-character)
    stLTTime  tSys;      // System time
    stLTTime  tUp;       // System uptime time
    stLTIFile ltf;       // Log Trace file info
} stLTInfo;
#define LT_SIZE_INFO    sizeof(stLTInfo)

typedef struct __attribute__((packed)) STRUCT_LOG_TRACE_DATA_MESSAGE {
    size_t   szMsg;
    char    *msg;
} stLTMsg;
#define LT_SIZE_MSG    sizeof(stLTMsg)

typedef struct __attribute__((packed)) STRUCT_LOG_TRACE_DATA_DUMP {
    size_t   szMsg;
    size_t   szData;
    char    *msg;
    char    *data;
} stLTDump;
#define LT_SIZE_DUMP    sizeof(stLTDump)

typedef struct __attribute__((packed)) STRUCT_LOG_TRACE_DATA {
    stLTInfo  info;
    void     *data;
} stLTData;
#define LT_SIZE_DATA    sizeof(stLTData)

typedef struct STRUCT_LOG_TRACE_NODE {
    void     *front;
    void     *next;
    void     *value;
} stLTNode;
#define LT_SIZE_NODE    sizeof(stLTNode)

typedef struct STRUCT_LOG_TRACE_HANDLE {
    stLTNode  *head;
    stLTNode  *tail;
    void      *mtx;
    void      *sem;
} stLTHandle;

void *ltHandleCreate(void);
void  ltHandleDestroy(stLTHandle *hLT, void (*destroy)(void *));

int   ltQueSize(stLTHandle *hLT);
int   ltQuePushTail(stLTHandle *hLT, void *value);
void *ltQuePopHead(stLTHandle *hLT);

void ltDestroy(void);
int  ltInitailize(const char *path);

int ltMsg(const char *tag, int level, const char *path, int line, const char *fmt, ...);
int ltDump(const char *tag, int level, const char *path, int line, void *data, size_t size, const char *fmt, ...);

#endif /* _LOG_AND_TRACE_HEADER */

