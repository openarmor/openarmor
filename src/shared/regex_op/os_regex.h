/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* See README for details */

#ifndef __OS_REGEX_H
#define __OS_REGEX_H

/* size_t */
#include <stddef.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

/* OSRegex_Compile flags */
#define OS_RETURN_SUBSTRING     0000200
#define OS_CASE_SENSITIVE       0000400

/* Pattern maximum size */
#define OS_PATTERN_MAXSIZE      2048

/* Error codes */
#define OS_REGEX_REG_NULL       1
#define OS_REGEX_PATTERN_NULL   2
#define OS_REGEX_MAXSIZE        3
#define OS_REGEX_OUTOFMEMORY    4
#define OS_REGEX_STR_NULL       5
#define OS_REGEX_BADREGEX       6
#define OS_REGEX_BADPARENTHESIS 7
#define OS_REGEX_NO_MATCH       8
#define OS_REGEX_NO_JIT         9
#define OS_REGEX_PATTERN_EMPTY  10

#define OS_CONVERT_REGEX        1
#define OS_CONVERT_MATCH        2

/* OSRegex structure */
typedef struct _OSRegex {
    int error;
    char **sub_strings;
    pcre2_code *regex;
    pcre2_match_data *match_data;
    size_t pattern_len;
    char *pattern;
    const char *(*exec_function)(const char *, struct _OSRegex *);
} OSRegex;

/* OSmatch structure */
typedef struct _OSMatch {
    int error;
    pcre2_code *regex;
    pcre2_match_data *match_data;
    size_t pattern_len;
    char *pattern;
    int (*exec_function)(const char *, size_t, struct _OSMatch *);
} OSMatch;

/* OSPcre2 structure */
typedef struct _OSPcre2 {
    int error;
    char **sub_strings;
    pcre2_code *regex;
    pcre2_match_data *match_data;
    size_t pattern_len;
    char *pattern;
    const char *(*exec_function)(const char *, struct _OSPcre2 *);
} OSPcre2;

/*** Prototypes ***/

/* Convert an openarmor pattern, match or regex,
 * to a PCRE2 pattern
 * Allowed map are:
 *      - OS_CONVERT_REGEX
 *      - OS_CONVERT_MATCH
 * Returns 1 on success or 0 on error.
 */
int OSRegex_Convert(const char *pattern, char **converted_pattern, uint32_t map);

/* Compile a regular expression to be used later
 * Allowed flags are:
 *      - OS_CASE_SENSITIVE
 *      - OS_RETURN_SUBSTRING
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSRegex_Compile(const char *pattern, OSRegex *reg, int flags);

/* Compare an already compiled regular expression with
 * a not NULL string.
 * Returns end of str on success or NULL on error.
 * The error code is set on reg->error.
 */
const char *OSRegex_Execute(const char *str, OSRegex *reg) __attribute__((nonnull(2)));

/* Release all the memory created by the compilation/execution phases */
void OSRegex_FreePattern(OSRegex *reg) __attribute__((nonnull));


/* Release all the memory created to store the sub strings */
void OSRegex_FreeSubStrings(OSRegex *reg) __attribute__((nonnull));

/* This function is a wrapper around the compile/execute
 * functions. It should only be used when the pattern is
 * only going to be used once.
 * Returns 1 on success or 0 on failure.
 */
int OS_Regex(const char *pattern, const char *str);

/* Compile a pattern to be used later.
 * Allowed flags are:
 *      - OS_CASE_SENSITIVE
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSMatch_Compile(const char *pattern, OSMatch *reg, int flags);

/* Compare an already compiled pattern with a not NULL string.
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSMatch_Execute(const char *str, size_t str_len, OSMatch *reg)  __attribute__((nonnull(3)));

/* Release all the memory created by the compilation/execution phases */
void OSMatch_FreePattern(OSMatch *reg) __attribute__((nonnull));

int OS_Match2(const char *pattern, const char *str)  __attribute__((nonnull(2)));

/* Searches for pattern in the string */
int OS_WordMatch(const char *pattern, const char *str) __attribute__((nonnull));
#define OS_Match OS_WordMatch

/* Compile a PCRE2 expression to be used later
 * Allowed flags are the same as option in pcre2_compile
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSPcre2_Compile(const char *pattern, OSPcre2 *reg, int flags);

/* Compare an already compiled PCRE2 expression with
 * a not NULL string.
 * Returns end of str on success or NULL on error.
 * The error code is set on reg->error.
 */
const char *OSPcre2_Execute(const char *str, OSPcre2 *reg);

/* Release all the memory created by the compilation/execution phases */
void OSPcre2_FreePattern(OSPcre2 *reg);

/* Release all the memory created to store the sub strings */
void OSPcre2_FreeSubStrings(OSPcre2 *reg);

/* This function is a wrapper around the compile/execute
 * functions. It should only be used when the pattern is
 * only going to be used once.
 * Returns 1 on success or 0 on failure.
 */
int OS_Pcre2(const char *pattern, const char *str);

/* Split a string into multiples pieces, divided by a char "match".
 * Returns a NULL terminated array on success or NULL on error.
 */
char **OS_StrBreak(char match, const char *str, size_t size);

/* Returns the number of characters that both strings
 * have in similar (start at the beginning of them).
 */
size_t OS_StrHowClosedMatch(const char *str1, const char *str2);

/** Inline prototypes **/

/* Verifies if a string starts with the provided pattern.
 * Returns 1 on success or 0 on failure.
 */
int OS_StrStartsWith(const char *str, const char *pattern) __attribute__((nonnull));

/* Checks if a specific string is numeric (like "129544") */
int OS_StrIsNum(const char *str);

/* Checks if a specified char is in the following range:
 * a-z, A-Z, 0-9, _-.
 */
extern const unsigned char hostname_map[256];
#define isValidChar(x) (hostname_map[(unsigned char)x])

#endif /* __OS_REGEX_H */
