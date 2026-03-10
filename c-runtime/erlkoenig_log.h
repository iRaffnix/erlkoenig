/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * erlkoenig_log.h - Logging macros for erlkoenig_rt.
 *
 * All output goes to stderr (stdout is the port protocol channel).
 *
 * Log levels (runtime, via ERLKOENIG_LOG env var):
 *   error   - only errors (default)
 *   warn    - errors + warnings
 *   info    - errors + warnings + info
 *   debug   - everything
 *
 * Call erlkoenig_log_init() once at startup to read ERLKOENIG_LOG.
 */

#ifndef ERLKOENIG_LOG_H
#define ERLKOENIG_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

enum erlkoenig_log_level {
	ERLKOENIG_LOG_ERROR = 0,
	ERLKOENIG_LOG_WARN  = 1,
	ERLKOENIG_LOG_INFO  = 2,
	ERLKOENIG_LOG_DEBUG = 3,
};

static enum erlkoenig_log_level g_log_level = ERLKOENIG_LOG_ERROR;

static inline void erlkoenig_log_init(void)
{
	const char *env = getenv("ERLKOENIG_LOG");

	if (!env)
		return;
	if (strcmp(env, "debug") == 0)
		g_log_level = ERLKOENIG_LOG_DEBUG;
	else if (strcmp(env, "info") == 0)
		g_log_level = ERLKOENIG_LOG_INFO;
	else if (strcmp(env, "warn") == 0)
		g_log_level = ERLKOENIG_LOG_WARN;
	else if (strcmp(env, "error") == 0)
		g_log_level = ERLKOENIG_LOG_ERROR;
}

#define LOG_ERR(fmt, ...) \
	fprintf(stderr, "erlkoenig_rt: ERROR: " fmt "\n", ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) do { \
	if (g_log_level >= ERLKOENIG_LOG_WARN) \
		fprintf(stderr, "erlkoenig_rt: WARN:  " fmt "\n", ##__VA_ARGS__); \
} while (0)

#define LOG_INFO(fmt, ...) do { \
	if (g_log_level >= ERLKOENIG_LOG_INFO) \
		fprintf(stderr, "erlkoenig_rt: INFO:  " fmt "\n", ##__VA_ARGS__); \
} while (0)

#define LOG_DBG(fmt, ...) do { \
	if (g_log_level >= ERLKOENIG_LOG_DEBUG) \
		fprintf(stderr, "erlkoenig_rt: DBG:   " fmt "\n", ##__VA_ARGS__); \
} while (0)

/*
 * Log a syscall failure. Captures errno immediately.
 * Always logged (ERROR level).
 * Usage: LOG_SYSCALL("clone");
 */
#define LOG_SYSCALL(name) \
	LOG_ERR("%s: %s (errno=%d)", name, strerror(errno), errno)

#endif /* ERLKOENIG_LOG_H */
