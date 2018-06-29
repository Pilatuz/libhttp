/**
 * @file
 * @brief Miscellaneous tools implementation.
 * @author Sergey Polichnoy <pilatuz@gmail.com>
 */
#include "misc.h"

#if defined(FREESCALE_MQX)  // MQX
# include <mqx.h>
# include <fio.h>
# include <rtcs.h>
#elif defined(__linux__)    // Linux
# include <sys/time.h>
# include <sys/select.h>
# include <pthread.h>
# include <unistd.h>
# include <stdarg.h>
# include <stdio.h>
#else
# error Unsupported platform
#endif


// log stream
#ifndef LOG_STREAM
/**
 * @brief Log output stream.
 *
 * By default defined as `stdout` but can be specified as `stderr` or any
 * other stream-like variable. In this case that variable should be available
 * inside `misc.c` file.
 *
 * Note, this parameter can be customized only once, for whole application.
 *
 * @see @ref logging_page
 */
# define LOG_STREAM stdout // fallback to stdout
#endif // LOG_STREAM


/*
 * Filepath separator.
 *
 * On Linux it is '/'=0x2f.
 * On Windows it is '\\'=0x5c.
 */
#ifndef LOG_PATH_SEPARATOR
# if defined(__linux__)
/**
 * @brief Log filepath separator.
 *
 * This is filepath separator which is used to strip parent directories from
 * file names (if no #LOG_FULL_FILENAME defined).
 *
 * On Linux platform it is defined as `'/'`,
 * on Windows it is defined as `'\\'`.
 *
 * Note, this parameter can be customized only once, for whole application.
 *
 * @see @ref logging_page
 * @see #LOG_FULL_FILENAME
 */
#  define LOG_PATH_SEPARATOR ('/')  // fallback to Linux '/'
# else
#  define LOG_PATH_SEPARATOR ('\\') // fallback to Windows '\'
# endif
#endif // LOG_PATH_SEPARATOR


/*
 * Define this to omit thread identifier.
 */
#ifndef LOG_NO_THREAD_ID
/**
 * @brief Do not print thread identifiers.
 *
 * If this macro is defined then no thread identifier is shown in log messages.
 *
 * Note, this parameter can be customized only once, for whole application.
 *
 * @see @ref logging_page
 * @see #LOG_NO_TIMESTAMP
 */
# define LOG_NO_THREAD_ID // only for doxygen
# undef LOG_NO_THREAD_ID
#endif // LOG_NO_THREAD_ID


/*
 * Define this to omit timestamps.
 */
#ifndef LOG_NO_TIMESTAMP
/**
 * @brief Do not print timestamps.
 *
 * If this macro is defined then no timestamp is shown in log messages.
 *
 * Note, this parameter can be customized only once, for whole application.
 *
 * @see @ref logging_page
 * @see #LOG_NO_THREAD_ID
 */
# define LOG_NO_TIMESTAMP // only for doxygen
# undef LOG_NO_TIMESTAMP
#endif // LOG_NO_TIMESTAMP


/*
 * Define this to use full source filenames.
 */
#ifndef LOG_FULL_FILENAME
/**
 * @brief Do not strip file names.
 *
 * If this macro is defined then full source file names are printed to log.
 *
 * Note, this parameter can be customized only once, for whole application.
 *
 * @see @ref logging_page
 * @see #LOG_PATH_SEPARATOR
 */
# define LOG_FULL_FILENAME // only for doxygen
# undef LOG_FULL_FILENAME
#endif // LOG_FULL_FILENAME


/*
 * Define this to do not flush log stream.
 */
#ifndef LOG_NO_FLUSH
/**
 * @brief Do not flush log stream after each message.
 *
 * If this macro is defined then there is no log stream flush after
 * each log message. This might produce incomplete log messages due
 * to buffering. On the other hand flushing may impact overall
 * application performance.
 *
 * Note, this parameter can be customized only once, for whole application.
 *
 * @see @ref logging_page
 */
# define LOG_NO_FLUSH
# undef LOG_NO_FLUSH
#endif // LOG_NO_FLUSH


/*
 * misc_log() implementation.
 */
void misc_log(const char *module,
              const char *level,
              const char *file, int line,
              const char *message, ...)
{
    FILE *stream = LOG_STREAM;

    // print thread identifier
#if !defined(LOG_NO_THREAD_ID)
# if defined(__MQX__)       // MQX
    fprintf(stream, "[%X] ",
            _task_get_id());
# elif defined(__linux__)   // Linux
    // TODO: get pthread identifier
    fprintf(stream, "[%d] ",
            getpid());
# else
#  error Unsupported platform
# endif
#endif // LOG_NO_THREAD_ID

    // print timestamp
#if !defined(LOG_NO_TIMESTAMP)
# if defined(__MQX__)        // MQX
    TIME_STRUCT now;
    _time_get_elapsed(&now);
    fprintf(stream, "%3d.%03d ",
            now.SECONDS,
            now.MILLISECONDS);
# elif defined(__linux__)    // Linux
    struct timeval tv;
    if (0 != gettimeofday(&tv, 0))
    {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    }
    static time_t start_time = 0;
    if (!start_time)
        start_time = tv.tv_sec;
    fprintf(stream, "%.3ld.%06ld ",
            tv.tv_sec - start_time,
            tv.tv_usec);
# else
#  error Unsupported platform
# endif
#endif // LOG_NO_TIMESTAMP

    const char *filename = file;
#ifndef LOG_FULL_FILENAME
    // keep the filename only
    for (; *file; ++file)
    {
        if (LOG_PATH_SEPARATOR == *file)
            filename = file+1;
    }
#endif // LOG_FULL_FILENAME

    if (module) fprintf(stream, "<%s> ", module);
    fprintf(stream, "%s (%s#%d): ", level, filename, line);

    va_list args;
    va_start(args, message);
    vfprintf(stream, message, args);
    va_end(args);

#ifndef LOG_NO_FLUSH
    fflush(stream);
#endif // LOG_NO_FLUSH
}


/*
 * misc_time_ms() implementation.
 */
uint32_t misc_time_ms(void)
{
#if defined(__MQX__)        // MQX
    TIME_STRUCT t;
    _time_get_elapsed(&t);
    return t.SECONDS * 1000
         + t.MILLISECONDS;
#elif defined(__linux__)    // Linux
    struct timeval tv;
    if (!!gettimeofday(&tv, 0))
        return 0; // TODO: report error?
    return tv.tv_sec*1000
         + tv.tv_usec/1000;
#else
# error Unsupported platform
#endif // __MQX__
}


/*
 * misc_closesocket() implementation.
 */
int misc_closesocket(int fd)
{
#if defined(__MQX__)        // MQX
    return shutdown(fd, FLAG_CLOSE_TX);
#elif defined(__linux__)    // Linux
    return close(fd);
#else
# error Unsupported platform
#endif
}


/*
 * misc_select_read() implementation.
 */
int misc_select_read(const int *fds, int n_fds,
                     int *fd, int timeout_ms)
{
#if defined(__MQX__) // MQX
    int fds[2];
    int n = 0;

    // fill array
    if (fd1 >= 0)
        fds[n++] = fd1;
    if (fd2 >= 0)
        fds[n++] = fd2;

    int err = RTCS_selectset(fds, n, timeout_ms);
    if (err <= 0)
        return err;

    *fd = err; // OK
    return err;
#elif defined(__linux__) // Linux
    struct timeval to;
    if (timeout_ms >= 0)
    {
        to.tv_sec = (timeout_ms / 1000);
        to.tv_usec = (timeout_ms % 1000) * 1000;
    }
    else
    {
        to.tv_sec = 0;
        to.tv_usec = 0;
    }

    // accept set
    fd_set read_fds;
    FD_ZERO(&read_fds);
    int max_fd = 0;
    for (int i = 0; i < n_fds; ++i)
    {
        if (fds[i] >= 0)
        {
            FD_SET(fds[i], &read_fds);
            if (max_fd < fds[i])
                max_fd = fds[i];
        }
    }

    const int err = select(max_fd+1, &read_fds, 0, 0,
                           (timeout_ms >= 0) ? &to : 0);
    if (err <= 0)
        return err;

    if (fd)
    for (int i = 0; i < n_fds; ++i)
    {
        if (FD_ISSET(fds[i], &read_fds))
        {
            *fd = fds[i];
            break;
        }
    }

    return err;
#else
# error Unsupported platform
#endif
}
