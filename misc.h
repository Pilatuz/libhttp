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


// log level
#ifndef LOG_LEVEL
/**
 * @brief Maximum log level to show.
 *
 * All log levels less than or equal to this value are shown.
 * All log levels greater than this value are dropped.
 *
 * There are the following log levels:
 * - `0` - FATAL() shows *fatal* messages
 * - `1` - ERROR() shows *error* messages
 * - `2` - WARN() shows *warning* messages
 * - `3` - INFO() shows *info* messages
 * - `4` - DEBUG() shows *debug* messages
 * - `5` - TRACE() shows *trace* messages
 * - `9` - usually shows all messages
 *
 * Log level should be defined in the following way:
 *
 * ```{.c}
 * #undef LOG_LEVEL
 * #define LOG_LEVEL 3 // INFO only
 * #include "misc.h"
 * ```
 *
 * If LOG_ENABLED() macro is not re-defined then
 * usually all dropped log messages are completely
 * wiped out at compile time.
 *
 * @see @ref logging_page
 * @see LOG_ENABLED()
 * @see LOG_MODULE
 */
# define LOG_LEVEL 9 // fallback to all messages
#endif // LOG_LEVEL


// log level check
#ifndef LOG_ENABLED
/**
 * @brief Check the log level is enabled.
 *
 * This macro is a customization point for the log level check.
 * By default it just checks the log level at compile time.
 *
 * For example, runtime checks can be done in the following way:
 *
 * ```{.c}
 * extern int my_log_level; // runtime log level
 * #define LOG_ENABLED(level) (level <= LOG_LEVEL && level <= my_log_level)
 * #include "misc.h"
 * ```
 * Having this define it is possible to change log level at runtime by
 * setting the corresponding value to `my_log_level` variable.
 *
 * @param level Log level to check.
 *
 * @see @ref logging_page
 * @see LOG_LEVEL
 * @see LOG_MODULE
 */
# define LOG_ENABLED(level) (level <= LOG_LEVEL)
#endif


// log module name
#ifndef LOG_MODULE
/**
 * @brief Log module name.
 *
 * `NULL` can be used if there is no module name.
 *
 * Log module name should be defined in the following way:
 *
 * ```{.c}
 * #undef LOG_MODULE
 * #define LOG_MODULE "http"
 * #include "misc.h"
 * ```
 *
 * @see @ref logging_page
 * @see LOG_ENABLED()
 * @see LOG_MODULE
 */
# define LOG_MODULE 0 // fallback to no log module
#endif // LOG_MODULE


// helpers (unused levels usually should be eliminated at compile-time)
// arguments are printf-like. at least format message should be provided!
#define TRACE(...) if (!LOG_ENABLED(5)) {} else misc_log(LOG_MODULE, "TRACE", __FILE__, __LINE__, __VA_ARGS__) /**< @hideinitializer @brief Fire the *trace* log message. @see @ref logging_page */
#define DEBUG(...) if (!LOG_ENABLED(4)) {} else misc_log(LOG_MODULE, "DEBUG", __FILE__, __LINE__, __VA_ARGS__) /**< @hideinitializer @brief Fire the *debug* log message. @see @ref logging_page */
#define  INFO(...) if (!LOG_ENABLED(3)) {} else misc_log(LOG_MODULE,  "INFO", __FILE__, __LINE__, __VA_ARGS__) /**< @hideinitializer @brief Fire the *info* log message. @see @ref logging_page */
#define  WARN(...) if (!LOG_ENABLED(2)) {} else misc_log(LOG_MODULE,  "WARN", __FILE__, __LINE__, __VA_ARGS__) /**< @hideinitializer @brief Fire the *warning* log message. @see @ref logging_page */
#define ERROR(...) if (!LOG_ENABLED(1)) {} else misc_log(LOG_MODULE, "ERROR", __FILE__, __LINE__, __VA_ARGS__) /**< @hideinitializer @brief Fire the *error* log message. @see @ref logging_page */
#define FATAL(...) if (!LOG_ENABLED(0)) {} else misc_log(LOG_MODULE, "FATAL", __FILE__, __LINE__, __VA_ARGS__) /**< @hideinitializer @brief Fire the *fatal* log message. @see @ref logging_page */


/**
 * @brief Print log message.
 *
 * This function has the printf-like arguments.
 *
 * @param[in] module Module name.
 * @param[in] level Log level.
 * @param[in] file Source file name.
 * @param[in] line Source line number.
 * @param[in] message Message to print containing `printf`-like format options.
 *
 * @see @ref logging_page
 */
void misc_log(const char *module,
              const char *level,
              const char *file, int line,
              const char *message, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 5, 6)))
#endif
;


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
 * @page logging_page Logging
 *
 * Extensive logging is very helpful in debugging. Using this module it is
 * possible to produce very customizable and readable logs.
 *
 * @tableofcontents
 *
 * @section logging_levels Log levels
 *
 * First of all there are a few log level with corresponding helper macro:
 * - TRACE() fires *trace* messages
 * - DEBUG() fires *debug* messages
 * - INFO() fires *info* messages
 * - WARN() fires *warning* messages
 * - ERROR() fires *error* messages
 * - FATAL() fires *fatal* messages
 *
 * They are listed in order of importance from the less important to the most
 * important. It is possible to limit the log levels with #LOG_LEVEL macro.
 * For example, If #LOG_LEVEL is defined as `3` then only *info*, *warning*,
 * *error* and *fatal* messages will be print. All other messages will be
 * ignored and usually they are completely wiped out at compile time.
 *
 * @section logging_customization Customization
 *
 * Logging module can be customized at a module level (just before `# include "misc.h"`):
 * - #LOG_LEVEL is used to specify minimum log level to print.
 * - LOG_ENABLED() is used to customize log level show condition.
 * - #LOG_MODULE is used to specify log module name.
 *
 * The following feature-macro can be customized only once at program level:
 * - #LOG_STREAM is used to specify log output stream, such as `stdout` or `stderr`.
 * - #LOG_PATH_SEPARATOR is used to customize filepath separator.
 * - #LOG_NO_THREAD_ID is used to disable printing thread identifiers.
 * - #LOG_NO_TIMESTAMP is used to disable printing timestamps.
 * - #LOG_FULL_FILENAME is used to print full source file name.
 * - #LOG_NO_FLUSH is used to disable log flush after each message.
 *
 * @section logging_example Example
 *
 * There is an example of usage logging module:
 *
 * ```{.c}
 * #undef LOG_LEVEL
 * #define LOG_LEVEL 9 // all messages!
 * #undef LOG_MODULE
 * #define LOG_MODULE "my_proc"
 * #include "misc.h"
 *
 * ...
 *
 * int foo(int arg)
 * {
 *   TRACE("entering foo(%d)\n", arg);
 *
 *   if (arg < 0)
 *   {
 *      ERROR("foo(): negative argument is not allowed!\n");
 *      return -1;
 *   }
 *
 *   if (arg == 0)
 *   {
 *      DEBUG("foo(): nothing to do\n");
 *      return 0;
 *   }
 *
 *   if (arg > 100)
 *   {
 *     WARN("foo(): argument is to big, truncating...\n");
 *     arg = 100;
 *   }
 *
 *   ...
 *   INFO("foo(): working with %d\n", arg);
 *
 *   TRACE("leaving foo()\n");
 * }
 * ```
 */


/**
 * @page compat_page Compatibility
 *
 * There are a few functions used as compatibility layer:
 * - misc_closesocket()
 * - misc_select_read()
 */
