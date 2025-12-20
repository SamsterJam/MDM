#ifndef LOG_H
#define LOG_H

#include <systemd/sd-journal.h>

#define log_debug(message) (sd_journal_print(LOG_DEBUG, "DEBUG:    %s", message))
#define log_info(message) (sd_journal_print(LOG_INFO, "INFO:     %s", message))
#define log_warn(message) (sd_journal_print(LOG_WARNING, "WARN:     %s", message))
#define log_error(message) (sd_journal_print(LOG_ERR, "ERROR:    %s", message))
#define log_critical(message) (sd_journal_print(LOG_CRIT, "CRITICAL: %s", message))

// For formatted logging
#define log_debugf(fmt, ...) (sd_journal_print(LOG_DEBUG, "DEBUG:    " fmt, ##__VA_ARGS__))
#define log_infof(fmt, ...) (sd_journal_print(LOG_INFO, "INFO:     " fmt, ##__VA_ARGS__))
#define log_warnf(fmt, ...) (sd_journal_print(LOG_WARNING, "WARN:     " fmt, ##__VA_ARGS__))
#define log_errorf(fmt, ...) (sd_journal_print(LOG_ERR, "ERROR:    " fmt, ##__VA_ARGS__))
#define log_criticalf(fmt, ...) (sd_journal_print(LOG_CRIT, "CRITICAL: " fmt, ##__VA_ARGS__))

#endif // LOG_H
