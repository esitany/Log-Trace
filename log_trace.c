
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>

#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <errno.h>

#include <libgen.h> // basename, dirname

#include <pthread.h>
#include <semaphore.h>

#include "log_trace.h"

//  #define LT_DBG        (1)
//  #define LT_SHOW_LOG   (1)

#if defined(LT_SHOW_LOG) && (LT_SHOW_LOG > 0)
  #define lDbg(fmt, ...) { \
    fprintf(stdout, "LT(%5d) > " fmt "\n", __LINE__,  ##__VA_ARGS__); \
    fflush(stdout); \
  }

  #define lWrn(fmt, ...) { \
    fprintf(stdout, "\x1b[33mLT(%5d) > " fmt "\x1B[0m\n", __LINE__,  ##__VA_ARGS__); \
    fflush(stdout); \
  }

  #define lErr(fmt, ...) { \
    fprintf(stdout, "\x1b[31mLT(%5d) > " fmt "[E=%s(%d)]\x1B[0m\n", __LINE__,  ##__VA_ARGS__, strerror(errno), errno); \
    fflush(stdout); \
  }
#else
  #define lDbg(...)  NULL
  #define lWrn(...)  NULL
  #define lErr(...)  NULL
#endif

#define LT_MARK_EOL       "\r\n"
#define LT_SIZE_EOL       strlen(LT_MARK_EOL)

typedef struct __attribute__((packed)) STRUCT_LOG_TRACE_CONFIG {
    uint32_t bRun : 1; //  0: 0, Run flag
    uint32_t size :30; //  1:31, file size
} stLTCfg;

typedef struct STRUCT_LOG_TRACE {
    int         fd;        // file descriptor
    stLTCfg     cfg;
    char        path[256]; // Log file path
    stLTHandle *hMsg;      // Log and Trace Message Queue handle

    pthread_mutex_t mtx;
} stLT;

void ltSaveLogMsg(stLTInfo *info, stLTMsg *msg);
void ltSaveLogDump(stLTInfo *info, stLTDump *dump);

static stLT *lt = NULL;
static char bLTColor = 0;

void ltHexDump(const char *title, void *pack, int size)
{
    int   idx = 0;

    char strTmp[4]    = {"\0"};
    char strAscii[32] = {"\0"};
    char strDump[64]  = {"\0"};
    char *dump        = NULL;

    dump = (char *)pack;
    if ((size > 0) && (pack != NULL)) {
        fprintf(stdout, " ***** %s %d bytes *****\n", (title == NULL) ? "None" : title, size);
        fflush(stdout);

        memset(strDump, 0, 64);
        memset(strAscii, 0, 32);

        for(idx = 0; idx < size; idx++) {
            if    ((0x1F < dump[idx]) && (dump[idx] < 0x7F) ) { strAscii[idx & 0x0F] = dump[idx]; }
            else                                              { strAscii[idx & 0x0F] = 0x2E;
            }

            snprintf(strTmp, 4, "%02X ", (unsigned char)dump[idx]);
            strcat(strDump, strTmp);
            if( (idx != 0) && ((idx & 0x03) == 0x03)) { strcat(strDump, " "); }

            if((idx & 0x0F) == 0x0F) {
                fprintf(stdout, "%12s <0x%04X> %s%s\n", "", (idx & 0xFFF0), strDump, strAscii);
                fflush(stdout);
                memset(strDump, 0, 64);
                memset(strAscii, 0, 32);
            }
        }

        if ((size > 0) && (((size - 1) & 0x0F) != 0x0F)) {
            for(idx = strlen(strDump) ; idx < 52; idx++) {
                strDump[idx] = 0x20;
            }
            fprintf(stdout, "%12s <0x%04X> %s%s\n", "", (size & 0xFFF0), strDump, strAscii);
            fflush(stdout);
        }

        fprintf(stdout, "\n");
        fflush(stdout);
    }
}

void *ltHandleCreate(void)
{
    stLTHandle *hLT = NULL;

    hLT = (stLTHandle *)malloc(sizeof(stLTHandle) + 1);
    if (hLT == NULL) {
        lErr("Allocate failed...");
    }
    else {
        hLT->mtx = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
        if ( (hLT->mtx == NULL)
          || (pthread_mutex_init((pthread_mutex_t *)hLT->mtx, NULL) != 0) ) {
            lErr("pthread_mutex_init() failed...");
            if (hLT->mtx != NULL) free(hLT->mtx);

            free(hLT);
            hLT = NULL;
        }
        else {
            hLT->sem = (sem_t *)malloc(sizeof(sem_t));
            if ( (hLT->sem == NULL)
              || (sem_init((sem_t *)hLT->sem, 0, 0) != 0)) {
                lErr("pthread_mutex_init() failed...");
                if (hLT->sem != NULL) free(hLT->sem);

                pthread_mutex_destroy((pthread_mutex_t *)hLT->mtx);
                free(hLT->mtx);

                free(hLT);
                hLT = NULL;
            }
            else {
                hLT->head = NULL;
                hLT->tail = NULL;
            }
        }
    }

    return hLT;
}

void ltHandleDestroy(stLTHandle *hLT, void (*destroy)(void *))
{
    int val = 0,
        ret = 0;

    if (hLT) {
        do {
            usleep(50000);
            val = 0;
            ret = sem_getvalue((sem_t *)hLT->sem, &val);
        } while ((ret != -1) && (val > 0));

        pthread_mutex_destroy((pthread_mutex_t *)hLT->mtx);
        sem_destroy((sem_t *)hLT->sem);

        free(hLT->mtx);
        free(hLT->sem);

        free(hLT);
        hLT = NULL;
    }
}

int ltQueSize(stLTHandle *hLT)
{
    int ret = 0,
        val = 0;

    if (hLT == NULL) {
        lWrn("Queue handle is not initailize!!!");
        ret = -EINVAL;
    }
    else {
        if (sem_getvalue((sem_t *)hLT->sem, &val) == -1) {
            lErr("sem_getvalue() failed...");
            ret = -EFAULT;
        }
        else {
            ret = val;
        }
    }

    return ret;
}

int ltQuePushTail(stLTHandle *hLT, void *value)
{
    int ret = 0;

    stLTNode *node = NULL;

    if (hLT == NULL) {
        lWrn("Queue handle is not initailize!!!");
        ret = -EINVAL;
    }
    else if (value == NULL) {
        lWrn("Log and trace data is not exist!!!");
        ret = -EINVAL;
    }
    else {
        node = (stLTNode *)malloc(LT_SIZE_NODE);
        if (node == NULL) {
            lErr("Allocate failed...");
            ret = -EFAULT;
        }
        else {
            node->front = NULL;
            node->next  = NULL;
            node->value = value;

            pthread_mutex_lock(hLT->mtx);

            if (hLT->tail == NULL) { // Queue is empty
                hLT->tail = (stLTNode *)node;
                hLT->head = (stLTNode *)node;
            }
            else {
                ((stLTNode *)hLT->tail)->next = (stLTNode *)node;

                node->front = (stLTNode *)hLT->tail;

                hLT->tail = (stLTNode *)node;
            }

            sem_post((sem_t *)hLT->sem);

            pthread_mutex_unlock(hLT->mtx);

            ret = ltQueSize(hLT);
        }
    }

    return ret;
}

void *ltQuePopHead(stLTHandle *hLT)
{
    void     *value = NULL;

    stLTNode *head  = NULL;

    if (hLT) {
        if (sem_trywait((sem_t *)hLT->sem) != 0) {
            if (errno != EAGAIN)
                lErr("sem_trywait() failed...");
        }
        else {
            pthread_mutex_lock(hLT->mtx);

            head = (stLTNode *)hLT->head;
            if (head != NULL) {
                if (hLT->tail == head) {
                    hLT->head = hLT->tail = NULL;
                }
                else {
                    hLT->head = head->next;
                    hLT->head->front = NULL;
                }

                value = head->value;
                free(head);
            }

            pthread_mutex_unlock(hLT->mtx);
        }
    }

    return value;
}

int ltLogType(int type)
{
    return ((type < LT_MSG) || (LT_DUMP < type)) ? LT_UNKNOWN : type;
}

int ltLogLevel(int level)
{
    return ((level < LT_CRITICAL) || (LT_DEBUG < level)) ? LT_DEBUG : level;
}


#if defined(LOG_ANSI_COLOR_ENABLE)
  #define LT_DESC_UNKNOWN     LC_FG_CYAN   "Unkn" LC_RESET
  #define LT_DESC_DEBUG       LC_RESET     "Dbg " LC_RESET
  #define LT_DESC_INFORMATION LC_FG_MGENTA "Info" LC_RESET
  #define LT_DESC_ERROR       LC_FG_YELLOW "Err " LC_RESET
  #define LT_DESC_WARNING     LC_FG_YELLOW "Warn" LC_RESET
  #define LT_DESC_CRITICAL    LC_FG_RED    "Crit" LC_RESET
#else
  #define LT_DESC_UNKNOWN     "Unkn"
  #define LT_DESC_DEBUG       "Dbg"
  #define LT_DESC_INFORMATION "Info"
  #define LT_DESC_ERROR       "Err"
  #define LT_DESC_WARNING     "Warn"
  #define LT_DESC_CRITICAL    "Crit"
//    #define LT_DESC_UNKNOWN     "Unknown"
//    #define LT_DESC_DEBUG       "Debug"
//    #define LT_DESC_INFORMATION "Information"
//    #define LT_DESC_ERROR       "Error"
//    #define LT_DESC_WARNING     "Warning"
//    #define LT_DESC_CRITICAL    "Critical"
#endif

char *ltLogLevelDesc(int level)
{
    char *desc = NULL;
    switch(level) {
    case LT_DEBUG    : desc = LT_DESC_DEBUG;       break;
    case LT_INFO     : desc = LT_DESC_INFORMATION; break;
    case LT_WARN     : desc = LT_DESC_WARNING;     break;
    case LT_ERR      : desc = LT_DESC_ERROR;       break;
    case LT_CRITICAL : desc = LT_DESC_CRITICAL;    break;
    default          : desc = LT_DESC_UNKNOWN;     break;
    }

    return desc;
}

int ltSysTime(stLTTime *ltt)
{
    int ret = 0;

    struct timespec ts = { .tv_sec = 0, };

    if (ltt == NULL) {
        lWrn("Not Exist Log and trace time data !!!");
        ret = -EINVAL;
    }
    else {
        ltt->sec  = 0;
        ltt->usec = 0;

        if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
            ltt->sec  = ts.tv_sec;
            ltt->usec = (uint32_t)(ts.tv_nsec / 1000);
        }
        else {
            lErr("clock_gettime(CLOCK_REALTIME, ) failed...");
            ret = -EFAULT;
        }
    }

    return ret;
}

int ltUpTime(stLTTime *ltt)
{
    int ret = 0;

    struct timespec ts = { .tv_sec = 0, };

    if (ltt == NULL) {
        lWrn("Not Exist Log and trace time data !!!");
        ret = -EINVAL;
    }
    else {
        ltt->sec  = 0;
        ltt->usec = 0;

        if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
            ltt->sec  = ts.tv_sec;
            ltt->usec = (uint32_t)(ts.tv_nsec / 1000);
        }
        else {
            lErr("clock_gettime(CLOCK_MONOTONIC_RAW, ) failed...");
            ret = -EFAULT;
        }
    }

    return ret;
}

int ltFileInfo(const char *path, int line, stLTIFile *ltf)
{
    int ret = 0,
        idx = 0;

    char *bpath = NULL,
         *bname = NULL;
#if defined(LT_DBG) && (LT_DBG > 1)
    char *dpath = NULL,
         *dname = NULL;
#endif

    if (ltf == NULL) {
        lWrn("Not Exist Log and trace file info data !!!");
        ret = -EINVAL;
    }
    else {
        ltf->line = 0;
        memset(ltf->name, 0, LT_FILE_LENGTH);

        bpath  = strdup(path);
        bname  = basename(bpath);
#if defined(LT_DBG) && (LT_DBG > 1)
        dpath  = strdup(path);
        dname  = dirname(dpath);

        lDbg("Dir = %s, base = %s", dname, bname);
        free(dpath);
#endif
        ltf->line = line;
//          snprintf(ltf->name, 16, "%s", bname);
        for (idx = 0; ((idx < (LT_FILE_LENGTH - 1)) && (bname[idx] != 0x00)); idx++) {
            ltf->name[idx] = bname[idx];
        }

        free(bpath);
    }

    return ret;
}

int ltIsRun(void)
{
    int ret = 0;

    if (lt) {
        ret = lt->cfg.bRun;
    }

    return ret;
}

void ltLock(void)
{
    if (lt) {
        pthread_mutex_lock(&lt->mtx);
    }
}

void ltUnLock(void)
{
    if (lt) {
        pthread_mutex_unlock(&lt->mtx);
    }
}

void ltQueMsgDestroy(void *value)
{
    stLTMsg  *msg  = NULL;
    stLTDump *dump = NULL;
    stLTData *ltd  = NULL;

    if (value != NULL) {
        ltd = (stLTData *)value;

        if (ltd->data) {
            switch(ltd->info.cfg.type) {
            case LT_MSG  :
                msg = (stLTMsg *)ltd->data;
                if (msg->msg) free(msg->msg);
                break;
            case LT_DUMP :
                dump = (stLTDump *)ltd->data;
                if (dump->msg)  free(dump->msg);
                if (dump->data) free(dump->data);
                break;
            default      : break;
            }
            free(ltd->data);
        }

        free(ltd);
    }
}

int ltPushMsg(const char *tag, int level, const char *path, int line, const char *msg)
{
    int ret = 0;

    stLTData *ltd   = NULL;
    stLTMsg  *ltMsg = NULL;

    if (ltIsRun()) {
        ltd = (stLTData *)malloc(LT_SIZE_DATA);
        if (ltd == NULL) {
            lErr("Allocate failed...");
            ret = -EFAULT;
        }
        else {
            memset(&ltd->info, 0, LT_SIZE_INFO);
            ltd->info.cfg.type  = LT_MSG;
            ltd->info.cfg.level = ltLogLevel(level);

            ltd->data = (stLTMsg *)malloc(LT_SIZE_MSG);
            if (ltd->data == NULL) {
                lErr("Allocate failed...");
                ret = -EFAULT;
            }
        }

        if (ret >= 0) {
            ltMsg = (stLTMsg *)ltd->data;
            ltMsg->szMsg = strlen(msg);
            ltMsg->msg = NULL;

            if (ltMsg->szMsg > 0) {
                ltMsg->msg = (char *)malloc(ltMsg->szMsg + 1);
                if (ltMsg->msg == NULL) {
                    lErr("Allocate failed...");
                    ret = -EFAULT;
                }
                else {
                    snprintf((char *)ltMsg->msg, ltMsg->szMsg + 1, "%s", msg);
                }
            }
        }

        if (ret >= 0) {
            snprintf(ltd->info.tag, 9, "%s", tag);

            ltFileInfo(path, line, &ltd->info.ltf);

            ltSysTime(&ltd->info.tSys);
            ltUpTime(&ltd->info.tUp);

            ret = ltQuePushTail(lt->hMsg, ltd);
        }

        if (ret < 0) {
            ltQueMsgDestroy(ltd);
        }
    }


    return ret;
}

int ltMsg(const char *tag, int level, const char *path, int line, const char *fmt, ...)
{
    int ret = 0;

    va_list ap;

    char err[128] = {"\0"};
    char msg[LT_MAX_SIZE_MSG] = {"\0"};

    if (ltIsRun()) {
        ltLock();

        va_start(ap, fmt);
        vsnprintf(msg, LT_MAX_SIZE_MSG - 128, fmt, ap);
        va_end(ap);

        if (level == LT_ERR) {
            snprintf(err, 128, "[errno=%d(%s)]", errno, strerror(errno));
            if ((strlen(err) + strlen(msg)) < LT_MAX_SIZE_MSG) {
                strcat(msg, err);
            }
        }

    #if defined(LT_DBG)
        lDbg("MSG(%s[%d] >> %s)", path, line, msg);
    #endif
        ret = ltPushMsg(tag, level, path, line, msg);

        ltUnLock();
    }

    return ret;
}

int ltPushDump(const char *tag, int level, const char *path, int line, void *data, size_t size, const char *title)
{
    int ret = 0;

    stLTData *ltd  = NULL;
    stLTDump *dump = NULL;

    if (ltIsRun()) {
        ltd = (stLTData *)malloc(LT_SIZE_DATA);
        if (ltd == NULL) {
            lErr("Allocate failed...");
            ret = -EFAULT;
        }
        else {
            ltd->data = NULL;
            memset(&ltd->info, 0, LT_SIZE_INFO);
            ltd->info.cfg.type  = LT_DUMP;
            ltd->info.cfg.level = ltLogLevel(level);

            ltd->data = (stLTDump *)malloc(LT_SIZE_DUMP);
            if (ltd->data == NULL) {
                lErr("Allocate failed...");
                ret = -EFAULT;
            }
        }

        if (ret >= 0) {
            dump = (stLTDump *)ltd->data;
            dump->szMsg  = strlen(title);
            dump->szData = (size > LT_MAX_SIZE_DUMP) ? LT_MAX_SIZE_DUMP : size;
            dump->msg  = NULL;
            dump->data = NULL;

            if (dump->szMsg > 0) {
                dump->msg = (char *)malloc(dump->szMsg + 1);
                if (dump->msg == NULL) {
                    lErr("Allocate failed...");
                    ret = -EFAULT;
                }
                else {
                    snprintf((char *)dump->msg, dump->szMsg + 1, "%s", title);
                }
            }

            if (dump->szData > 0) {
                dump->data = (char *)malloc(dump->szData + 1);
                if (dump->data == NULL) {
                    lErr("Allocate failed...");
                    ret = -EFAULT;
                }
                else {
                    memcpy(dump->data, data, dump->szData);
                }
            }
        }

        if (ret >= 0) {
            snprintf(ltd->info.tag, 9, "%s", tag);

            ltFileInfo(path, line, &ltd->info.ltf);

            ltSysTime(&ltd->info.tSys);
            ltUpTime(&ltd->info.tUp);

           ret = ltQuePushTail(lt->hMsg, ltd);
        }

        if (ret < 0) {
            ltQueMsgDestroy(ltd);
        }
    }


    return ret;
}

int ltDump(const char *tag, int level, const char *path, int line, void *data, size_t size, const char *fmt, ...)
{
    int ret = 0;

    va_list ap;

    char err[128] = {"\0"};
    char msg[LT_MAX_SIZE_MSG] = {"\0"};

    if (ltIsRun()) {
        ltLock();

        va_start(ap, fmt);
        vsnprintf(msg, LT_MAX_SIZE_MSG, fmt, ap);
        va_end(ap);

        if (level == LT_ERR) {
            snprintf(err, 128, "[%s(%d)]", strerror(errno), errno);
            strcat(msg, err);
        }

    #if defined(LT_DBG)
        lDbg("Dump(%s[%d] >> %s)", path, line, msg);
    #endif
        ret = ltPushDump(tag, level, path, line, data, size, msg);
        ltUnLock();
    }

    return ret;
}

int ltMsgInfo(char *str, size_t size, stLTInfo *info)
{
    int ret = 0;
    time_t tsec = 0;
    struct tm tmLT;

    char tag[12] = {"\0"};
    char lv[16]  = {"\0"};

    char lusec[12] = {"\0"};
    char ltime[32] = {"\0"};

    char lline[ 8] = {"\0"};
    char lfile[32] = {"\0"};

    if (info) {
        snprintf(tag, 12, "%8s", info->tag);
        snprintf(lv,  16, "%s", ltLogLevelDesc(info->cfg.level));

        tsec = info->tSys.sec;
        localtime_r(&tsec, &tmLT);
        strftime(ltime, 32, "%H:%M:%S", &tmLT);
//          snprintf(lusec,  8, "%06d", info->tSys.usec / 100);
        snprintf(lusec,  8, "%06d", info->tSys.usec);

        snprintf(lfile, 32, "%15s", info->ltf.name);
        snprintf(lline,  8, "%5d", info->ltf.line);
    }

    if (str && (size > 0)) {
        ret = snprintf(str, size, "%8s.%6s|%8s|%4s|%15s|%5s", ltime, lusec, tag, lv, lfile, lline);
    #if defined(LOG_ANSI_COLOR_ENABLE)
        if (bLTColor) { ret = ret - ((info->cfg.level == LT_DEBUG) ? 8 : 9); }
    #endif
    }

    return ret;
}

#define LT_ROTATE_USE_TRUNCATE  (1)
int ltRotateLogfile(void)
{
#if defined( LT_ROTATE_USE_TRUNCATE ) && (LT_ROTATE_USE_TRUNCATE > 0)
    int ret = 0,
        fd_new = -1,
        fd_old = -1,
        szRead = 0;

    char path[256 + 8] = {"\0"};
    char buff[LT_READ_SIZE] = {"\0"};

#else
    int ret = 0;

    char path[256 + 8] = {"\0"};
#endif

    if (lt) {
        snprintf(path, 256 + 8, "%s.old", lt->path);
    #if defined( LT_ROTATE_USE_TRUNCATE ) && (LT_ROTATE_USE_TRUNCATE > 0)
        fd_old = open(lt->path, O_RDWR, (mode_t)00666);
        if (fd_old == -1) {
            lErr("open(%s) failed...", lt->path);
        }
        else {
            ret = (int)lseek(fd_old, (off_t)0, SEEK_SET);
            if (ret == -1) {
                lErr("lseek(%s, 0, SEEK_SET) failed...", lt->path);
            }

            fd_new = open(path, O_RDWR | O_CREAT | O_TRUNC, (mode_t)00666);
            if (fd_new == -1) {
                lErr("open(%s) failed...", path);
            }
            else {
                ret = (int)lseek(fd_new, (off_t)0, SEEK_SET);
                if (ret == -1) {
                    lErr("lseek(%s, 0, SEEK_SET) failed...", path);
                }
            }
        }

        if ((fd_old != -1) && (fd_new != -1)) {
            while ( (szRead = (int)read(fd_old, buff, LT_READ_SIZE)) > 0) {
                if (write(fd_new, buff, (size_t)szRead) == -1) {
                    lErr("write(%s, ...) failed...", path);
                    break;
                }
            }
        }

        if (fd_new != -1) {
            fsync(fd_new);
            close(fd_new);
        }

        if (fd_old != -1) {
            if (ftruncate(fd_old, (off_t)0) == -1) {
                lErr("ftruncate(%s, 0) failed...", lt->path);
            }

            close(fd_old);
        }

    #else
        ret = rename(lt->path, path);
        if (ret == -1) {
            lErr("rename(%s, %s) failed...", lt->path, path);
        }
    #endif
    }

    return ret;
}

int ltOpenLogfile(void)
{
    int fd  = -1,
        ret = 0,
        off = 0;

    size_t size = 0;
    char msg[256] = {"\0"};

    if (lt) {
        fd = open(lt->path, O_RDWR | O_CREAT, (mode_t)00666);
        if (fd == -1) {
            lErr("open(%s, ) failed...", lt->path);
        }
        else {
            lt->cfg.size = 0;

            lt->fd = fd;
            ret = (int)lseek(fd, 0, SEEK_END);
            if (ret == -1) {
                lErr("lseek(%s, 0, SEEK_END) failed...", lt->path);
            }
            else {
                off = ret;
                if (off > 0) {
                    ret = (int)lseek(fd, (off_t)off, SEEK_SET);
                    if (ret == -1) {
                        lErr("lseek(%s, %d, SEEK_SET) failed...", lt->path, off);
                    }
//                      lDbg("lseek(%s, %d, SEEK_SET)...%d", lt->path, off, ret);
                }

                snprintf(msg, 256, "----- ----- ----- Start Log file ----- ----- -----%s", LT_MARK_EOL);
                size = strlen(msg);

                write(fd, msg, size);
                fsync(fd);

                lt->cfg.size = (int)(off + size);
            }
        }
    }

    return fd;
}

void ltCloseLogfile(void)
{
    int fd  = -1;

    size_t size = 0;
    char msg[256] = {"\0"};

    if (lt) {
        fd = lt->fd;
        if (fd != -1) {
            snprintf(msg, 256, "----- ----- ----- Close Log file ----- ----- -----%s", LT_MARK_EOL);
            size = strlen(msg);

            write(fd, msg, size);
            fsync(fd);

            close(fd);

            lt->fd = -1;
        }
    }
}

int ltSaveLogfile(const void *msg, size_t size)
{
    int ret = 0,
        fd  = -1;

    if (lt) {
        fd = lt->fd;
        if (fd == -1) {
            fd = ltOpenLogfile();
        }
    }

    if (fd != -1) {
        if ((size + lt->cfg.size) > LT_MAX_SIZE_FILE) {
            ltCloseLogfile();

            ltRotateLogfile();

            fd = ltOpenLogfile();
        }
    }

    if (fd != -1) {
        if (msg && (size > 0)) {
            ret = (int)write(fd, msg, size);
            if (ret < 0) {
                lErr("write(fd=%d, ) failed...", fd);
            }
            else {
                fsync(fd);
                lt->cfg.size = lt->cfg.size + size;
            }
        }
    }

    return ret;
}

void ltSaveLogMsg(stLTInfo *info, stLTMsg *msg)
{
    char strInfo[128] = {"\0"};
    char str[LT_MAX_SIZE_MSG + 128] = {"\0"};

    ltMsgInfo(strInfo, 128, info);

    if (msg == NULL) {
        lWrn("Log Message is not exist!!!");
    }
    else if ((msg->msg == NULL) || (msg->szMsg < 1)) {
        lWrn("Log Message invaild(msg=%p, size=%d)", msg->msg, (int)msg->szMsg);
    }
    else {
        snprintf(str, LT_MAX_SIZE_MSG + 128, "<%s> %s%s", strInfo, msg->msg, LT_MARK_EOL);
        ltSaveLogfile(str, strlen(str));
    }
}

char *ltMsgAttach(char **dst, const char *src)
{
    size_t szSRC = 0,
           size  = 0;

    char *ptr = NULL;

    szSRC = strlen(src);
    if (szSRC > 0) {
        if (*dst == NULL) {
            size = szSRC + 1;
            ptr = (char *)malloc(size);
            if (ptr == NULL) {
                lErr("Allocate failed...");
            }
            else {
                strcpy(ptr, src);
                *dst = ptr;
            }
        }
        else {
            size = strlen(*dst) + szSRC + 1;
            ptr = (char *)realloc(*dst, size);
            if (ptr == NULL) {
                lErr("Allocate failed...");
            }
            else {
                strcat(ptr, src);
                *dst = ptr;
            }
        }
    }

    return ptr;
}

void ltSaveLogDump(stLTInfo *info, stLTDump *dump)
{
    int idx = 0;
    char ch = 0;

    size_t len = 0;

    char strHex[ 8] = {"\0"};
    char strASC[32] = {"\0"};
    char strRaw[64] = {"\0"};

    char strInfo[128] = {"\0"};
    char str[LT_MAX_SIZE_MSG] = {"\0"};

    char *msg = NULL;

    len = ltMsgInfo(strInfo, 128, info) + 2;
    snprintf(str,
             LT_MAX_SIZE_MSG,
             "<%s> ***** %s %d bytes *****%s",
             strInfo,
             (dump->msg == NULL) ? "None Title" : dump->msg,
             (int)dump->szData,
             LT_MARK_EOL);

    ltMsgAttach(&msg, str);

//      memset(strInfo, 0, 128);
    for (idx = 0; idx < len; idx++) {
        strInfo[idx] = 0x20; // space ' ';
    }
    strInfo[idx] = 0x00; // add NULL

    for (idx = 0; idx < dump->szData; idx++) {
        ch = dump->data[idx];
        if   ((0x1F < ch) && (ch < 0x7F) ) { strASC[idx & 0x0F] = ch; }
        else                               { strASC[idx & 0x0F] = 0x2E; /* mark . */}

        snprintf(strHex, 4, "%02X ", (unsigned char)ch);

        strcat(strRaw, strHex);
        if( (idx != 0) && ((idx & 0x03) == 0x03)) { strcat(strRaw, " "); }

        if((idx & 0x0F) == 0x0F) {
            snprintf(str, LT_MAX_SIZE_MSG, "%s <0x%04X> %52s %s%s",
                     strInfo, (int)(idx & 0xFFF0), strRaw, strASC, LT_MARK_EOL);
            ltMsgAttach(&msg, str);

            memset(strRaw, 0, 64);
            memset(strASC, 0, 32);
        }
    }

    if ((dump->szData > 0) && (((dump->szData - 1) & 0x0F) != 0x0F)) {
        for (idx = strlen(strRaw); idx < 52; idx++) {
            strRaw[idx] = 0x20; // space ' ';
        }

        snprintf(str, LT_MAX_SIZE_MSG, "%s <0x%04X> %52s %s%s",
                strInfo, (int)(dump->szData & 0xFFF0), strRaw, strASC, LT_MARK_EOL);
        ltMsgAttach(&msg, str);
    }

    if (msg != NULL) {
        ltSaveLogfile(msg, strlen((const char *)msg));

        free(msg);
    }
}

static void *thrdLTMsgQue(void *arg)
{
//      int ret = 0;
    stLTData *ltd = NULL;

    while (ltIsRun()) {
        if (ltQueSize(lt->hMsg) <= 0) {
            usleep(50000);
            continue;
        }

        ltd = (stLTData *)ltQuePopHead(lt->hMsg);
        if (ltd) {
//              lDbg("ltd=%p, ltd->data=%p", ltd, ltd->data);
            switch(ltd->info.cfg.type) {
            case LT_MSG  : ltSaveLogMsg(&ltd->info,  (stLTMsg *)ltd->data);  break;
            case LT_DUMP : ltSaveLogDump(&ltd->info, (stLTDump *)ltd->data); break;
            default      :
                lWrn("Not Support log type!!!");
                break;
            }

            ltQueMsgDestroy(ltd);
        }
        usleep(100);
    }

    while (ltQueSize(lt->hMsg) > 0) {
        ltd = (stLTData *)ltQuePopHead(lt->hMsg);
        if (ltd) {
            switch(ltd->info.cfg.type) {
            case LT_MSG  : ltSaveLogMsg(&ltd->info,  (stLTMsg *)ltd->data);  break;
            case LT_DUMP : ltSaveLogDump(&ltd->info, (stLTDump *)ltd->data); break;
            default      :
                lWrn("Not Support log type!!!");
                break;
            }

            ltQueMsgDestroy(ltd);
        }
    }

    ltCloseLogfile();

    pthread_exit((void *)0);
}

void ltDestroy(void)
{
    if (ltIsRun()) {
        lt->cfg.bRun = 0;
        usleep(300000);

        while (ltQueSize(lt->hMsg) > 0) {
            usleep(100000);
        }

        pthread_mutex_destroy(&lt->mtx);
        ltHandleDestroy(lt->hMsg, ltQueMsgDestroy);

        free(lt);
        lt = NULL;
    }
}

int ltMakeDir(const char *path)
{
    int ret = 0;

    struct stat sb;

    char *dpath = NULL,
         *dname = NULL;

    dpath  = strdup(path);
    dname  = dirname(dpath);

    if (access( dname, F_OK) == 0) {
        if (lstat(dname, &sb) != 0) {
            lErr("stat(%s, ) failed...", dname);
            ret = -EFAULT;
        }
        else {
            if ((sb.st_mode & S_IFMT) != S_IFDIR) {
                lWrn("%s is not directory!!!", dname);
                ret = -EINVAL;
            }
        }
    }
    else {
        ret = ltMakeDir((const char *)dname);
        if (ret == 0) {
            if ( mkdir(dname, (S_IWOTH | S_IROTH | S_IWGRP | S_IRGRP | S_IRWXU)) != 0) {
                lErr("mkdir(%s, ) failed...", dname);
                ret = -EFAULT;
            }
        }
    }

    free(dpath);
//      lDbg("%s() path = %s...%d", __FUNCTION__, path, ret);

    return ret;
}

int ltInitailize(const char *path)
{
    int ret = 0;

    char *env = NULL;

    pthread_t thrd;

    if (ltIsRun()) {
        lWrn("Log and Trace is already exist!!!");

        ltDestroy();
    }

    env = (char *)getenv("TERM");
    if (env) {
        bLTColor = (strstr(env, "color") != NULL) ? 1 : 0;
    }

    ret = ltMakeDir(path);
    if (ret >= 0) {
        lt = (stLT *)malloc(sizeof(stLT) + 1);
        if (lt == NULL) {
            lErr("Allocate failed...");
            ret = -EFAULT;
        }
        else {
            memset(lt, 0, sizeof(stLT));
            lt->hMsg = NULL;
            lt->fd   = -1;

            lt->cfg.bRun = 1;
            snprintf(lt->path, 256, "%s", path);

            ret = pthread_mutex_init(&lt->mtx, NULL);
            if ( ret != 0) {
                lErr("pthread_mutex_init() failed...");
                ret = -EFAULT;
            }
            else {
                lt->hMsg =(stLTHandle *)ltHandleCreate();
                if (lt->hMsg == NULL) {
                    lWrn("ltHandleCreate() failed!!!");
                    ret = -EFAULT;
                }
            }

            if (ret != 0) {
                ltDestroy();
            }
        }
    }

    if (ret >= 0) {
        if (pthread_create(&thrd, NULL, thrdLTMsgQue, NULL)) {
            lErr("pthread_create(LT MSG Queue thread) failed... ");
            ret = -EFAULT;

            ltDestroy();
        }
        else {
            if (pthread_detach(thrd)) {
                lErr("pthread_detach(LT MSG Queue thread) failed... ");
                ret = -EFAULT;

                ltDestroy();
            }
        }
//          lDbg("%s()...%d !!!", __FUNCTION__, ret);
    }

    return ret;
}

