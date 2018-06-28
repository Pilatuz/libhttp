/**
 * @file
 * @brief Miscellaneous tools interface.
 * @author Sergey Polichnoy <pilatuz@gmail.com>
 */
#ifndef __MISC_H__
#define __MISC_H__

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif // __cplusplus

/*
 * log levels:
 * - `1` - error messages
 * - `2` - warning messages
 * - `3` - info messages
 * - `4` - debug messages
 * - `5` - trace messages
 * - `9` - all messages
 */
#ifndef LOG_LEVEL
// fallback to all messages.
# define LOG_LEVEL 9
#endif // LOG_LEVEL


/*
 * log level check.
 */
#ifndef LOG_ENABLED
# define LOG_ENABLED(level) (level <= LOG_LEVEL)
#endif


/*
 * log module name.
 */
#ifndef LOG_MODULE
// fallback to no log module.
# define LOG_MODULE 0
#endif // LOG_MODULE


/**
 * @brief Print message to log.
 * @param[in] module Module name as LOG_MODULE.
 * @param[in] level Log level.
 * @param[in] file Source file name.
 * @param[in] line Source line number.
 * @param[in] message Message to print containing `printf`-like format options.
 */
void misc_log(const char *module,
              const char *level,
              const char *file, int line,
              const char *message, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 5, 6)))
#endif
;


// helpers (unused levels should be eliminated at compile-time)
// arguments are printf-like. at least format message should be provided.
#define TRACE(...) if (!LOG_ENABLED(5)) {} else misc_log(LOG_MODULE, "TRACE", __FILE__, __LINE__, __VA_ARGS__)
#define DEBUG(...) if (!LOG_ENABLED(4)) {} else misc_log(LOG_MODULE, "DEBUG", __FILE__, __LINE__, __VA_ARGS__)
#define  INFO(...) if (!LOG_ENABLED(3)) {} else misc_log(LOG_MODULE,  "INFO", __FILE__, __LINE__, __VA_ARGS__)
#define  WARN(...) if (!LOG_ENABLED(2)) {} else misc_log(LOG_MODULE,  "WARN", __FILE__, __LINE__, __VA_ARGS__)
#define ERROR(...) if (!LOG_ENABLED(1)) {} else misc_log(LOG_MODULE, "ERROR", __FILE__, __LINE__, __VA_ARGS__)
#define FATAL(...) if (!LOG_ENABLED(0)) {} else misc_log(LOG_MODULE, "FATAL", __FILE__, __LINE__, __VA_ARGS__)


/**
 * @brief Get elapsed time.
 *
 * This function is used to measure time intervals.
 *
 * Millisecond resolution and 32 bits is enough to measure up to 49 days.
 *
 * @return Time in milliseconds.
 */
uint32_t misc_time_ms(void);


/**
 * @brief Close socket.
 * @param fd Socket descriptor to close.
 * @return Zero on success.
 */
int misc_closesocket(int fd);


/**
 * @brief Check if any socket is ready to read/accept.
 * @param[in] fds Array of socket file descriptors to check.
 * @param[in] n_fds Number of socket file descriptors to check.
 * @param[out] fd Actual file descriptor selected.
 * @param[in] timeout_ms Wait timeout, milliseconds.
 * @return Negative in case of error. Zero if timed out.
 */
int misc_select_read(const int *fds, int n_fds,
                     int *fd, int timeout_ms);

// TODO: thread abstraction
// TODO: mutex, semaphore abstractions

#if defined(__cplusplus)
} // extern "C"
#endif // __cplusplus

#endif // __MISC_H__


/**
 * @module Logging
 *
 * The logging module designed to be simple and customizable.
 * There are a few logging levels:
 * - TRACE
 * - DEBUG
 * - INFO
 * - WARN
 * - ERROR
 * - FATAL
 *
 * Logging module can be customized in a few ways:
 * - LOG_LEVEL
 * - LOG_ENABLED
 * - LOG_MODULE
 * - LOG_STREAM
 * - LOG_PATH_SEPARATOR
 * - LOG_NO_THREAD_ID
 * - LOG_NO_TIMESTAMP
 * - LOG_FULL_FILENAME
 * - LOG_NO_FLUSH
 *
 * Examples:
 */
