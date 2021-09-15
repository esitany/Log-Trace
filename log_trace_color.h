
#ifndef _LOG_AND_TRACE_COLOR_HEADER
#define _LOG_AND_TRACE_COLOR_HEADER

// LOG ANSI escape Color code enable  
#define LOG_ANSI_COLOR_ENABLE       (1)

#if defined(LOG_ANSI_COLOR_ENABLE)
  #define LC_RESET          "\x1b[0m"
  #define LC_FG_BLACK       "\x1b[30m"
  #define LC_FG_RED         "\x1b[31m"
  #define LC_FG_GREEN       "\x1b[32m"
  #define LC_FG_YELLOW      "\x1b[33m"
  #define LC_FG_BLUE        "\x1b[34m"
  #define LC_FG_MGENTA      "\x1b[35m"
  #define LC_FG_CYAN        "\x1b[36m"
  #define LC_FG_WHITE       "\x1b[37m"
  #define LC_FG_RESET       "\033[39m"
  #define LC_BG_BLACK       "\033[40m"
  #define LC_BG_RED         "\033[41m"
  #define LC_BG_GREEN       "\033[42m"
  #define LC_BG_YELLOW      "\033[43m"
  #define LC_BG_BLUE        "\033[44m"
  #define LC_BG_PINK        "\033[45m"
  #define LC_BG_DARKBLUE    "\033[46m"
  #define LC_BG_WHITE       "\033[47m"
  #define LC_BG_RESET       "\033[49m"
#else 
  #define LC_RESET          " "
  #define LC_FG_BLACK       " "
  #define LC_FG_RED         " "
  #define LC_FG_GREEN       " "
  #define LC_FG_YELLOW      " "
  #define LC_FG_BLUE        " "
  #define LC_FG_MGENTA      " "
  #define LC_FG_CYAN        " "
  #define LC_FG_WHITE       " "
  #define LC_FG_RESET       " "
  #define LC_BG_BLACK       " "
  #define LC_BG_RED         " "
  #define LC_BG_GREEN       " "
  #define LC_BG_YELLOW      " "
  #define LC_BG_BLUE        " "
  #define LC_BG_PINK        " "
  #define LC_BG_DARKBLUE    " "
  #define LC_BG_WHITE       " "
  #define LC_BG_RESET       " "
#endif 

#endif /*  _LOG_AND_TRACE_COLOR_HEADER */


