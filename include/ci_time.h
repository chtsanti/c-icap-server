/*
 *  Copyright (C) 2004-2008 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA.
 */

#ifndef __C_ICAP_CI_TIME_H
#define __C_ICAP_CI_TIME_H

#include "c-icap.h"
#include <time.h>

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _WIN32

typedef struct timespec ci_clock_time_t;

#define CI_CLOCK_TIME_ZERO (ci_clock_time_t){0,0}

static inline void ci_clock_time_reset(ci_clock_time_t *t)
{
    *t = CI_CLOCK_TIME_ZERO;
}

static inline time_t ci_clock_time_to_seconds(ci_clock_time_t *tm) {
    return tm->tv_sec;
}

static inline void ci_clock_time_to_seconds2(ci_clock_time_t *tm, uint64_t *secs, uint64_t *nsecs) {
    if (secs)
        *secs = tm->tv_sec;
    if (nsecs)
        *nsecs = tm->tv_nsec;
}

static inline void ci_clock_time_to_epoch(ci_clock_time_t *tm, uint64_t *secs, uint64_t *nsecs) {
    ci_clock_time_to_seconds2(tm, secs, nsecs);
}

static inline int64_t ci_clock_time_diff_milli(ci_clock_time_t *tsstop, ci_clock_time_t *tsstart) {
    return
        ((int64_t)tsstop->tv_sec - (int64_t)tsstart->tv_sec) * 1000LL +
        ((int64_t)tsstop->tv_nsec - (int64_t)tsstart->tv_nsec) / 1000000LL;
}

static inline int64_t ci_clock_time_diff_micro(ci_clock_time_t *tsstop, ci_clock_time_t *tsstart) {
    return
        ((int64_t)tsstop->tv_sec - (int64_t)tsstart->tv_sec) * 1000000LL +
        ((int64_t)tsstop->tv_nsec - (int64_t)tsstart->tv_nsec) / 1000LL;
}

static inline int64_t ci_clock_time_diff_nano(ci_clock_time_t *tsstop, ci_clock_time_t *tsstart) {
    return
        ((int64_t)tsstop->tv_sec - (int64_t)tsstart->tv_sec) * 1000000000LL +
        ((int64_t)tsstop->tv_nsec - (int64_t)tsstart->tv_nsec);
}

static inline void ci_clock_time_get(ci_clock_time_t *t)
{
    clock_gettime(CLOCK_REALTIME, t);
}

static inline void ci_clock_time_add(ci_clock_time_t *dst, const ci_clock_time_t *t1, const ci_clock_time_t *t2) {
    dst->tv_nsec = t1->tv_nsec + t2->tv_nsec;
    dst->tv_sec = t1->tv_sec + t2->tv_sec + (dst->tv_nsec / 1000000000);
    dst->tv_nsec = dst->tv_nsec % 1000000000;
}

static inline void ci_clock_time_add_to(ci_clock_time_t *dst, const ci_clock_time_t *t1) {
    dst->tv_nsec += t1->tv_nsec;
    dst->tv_sec += t1->tv_sec + (dst->tv_nsec / 1000000000);
    dst->tv_nsec = dst->tv_nsec % 1000000000;
}

static inline void ci_clock_time_sub(ci_clock_time_t *dst, const ci_clock_time_t *t1, const ci_clock_time_t *t2) {
    //check if t2 greater/later than t1?
    if (t1->tv_nsec < t2->tv_nsec) {
        dst->tv_sec = t1->tv_sec - 1 - t2->tv_sec;
        dst->tv_nsec = 1000000000 + t1->tv_nsec - t2->tv_nsec;
    } else {
        dst->tv_sec = t1->tv_sec - t2->tv_sec;
        dst->tv_nsec = t1->tv_nsec - t2->tv_nsec;
    }
}

#else /*_WIN32*/

typedef LARGE_INTEGER ci_clock_time_t;
#define CI_CLOCK_TIME_ZERO (ci_clock_time_t){0}

CI_DECLARE_DATA extern LARGE_INTEGER _CI_CLOCK_FREQUENCY;
CI_DECLARE_FUNC(void) ci_performance_counter_to_epoch(LARGE_INTEGER *tm, uint64_t *secs, uint64_t *nsecs);

static inline void ci_clock_time_reset(ci_clock_time_t *t)
{
    *t = CI_CLOCK_TIME_ZERO;
}

static inline uint64_t ci_clock_time_to_seconds(ci_clock_time_t *tm) {
    return (tm->QuadPart / _CI_CLOCK_FREQUENCY.QuadPart);
}

static inline void ci_clock_time_to_seconds2(ci_clock_time_t *tm, uint64_t *secs, uint64_t *nsecs) {
    if (secs)
        *secs = tm->QuadPart / _CI_CLOCK_FREQUENCY.QuadPart;
    if (nsecs)
        *nsecs = ((tm->QuadPart % _CI_CLOCK_FREQUENCY.QuadPart) * 1000000000LL) / _CI_CLOCK_FREQUENCY.QuadPart;
}

static inline void ci_clock_time_to_epoch(ci_clock_time_t *tm, uint64_t *secs, uint64_t *nsecs) {
    ci_performance_counter_to_epoch(tm, secs, nsecs);
}

static inline int64_t ci_clock_time_diff_nano(ci_clock_time_t *tsstop, ci_clock_time_t *tsstart) {
    int64_t value = (tsstop->QuadPart - tsstart->QuadPart) * 1000000000LL;
    return (value / _CI_CLOCK_FREQUENCY.QuadPart);
}

static inline int64_t ci_clock_time_diff_micro(ci_clock_time_t *tsstop, ci_clock_time_t *tsstart) {
    int64_t value = (tsstop->QuadPart - tsstart->QuadPart) * 1000000LL;
    return (value / _CI_CLOCK_FREQUENCY.QuadPart);
}

static inline int64_t ci_clock_time_diff_milli(ci_clock_time_t *tsstop, ci_clock_time_t *tsstart) {
    int64_t value = (tsstop->QuadPart - tsstart->QuadPart) * 1000LL;
    return (value / _CI_CLOCK_FREQUENCY.QuadPart);
}

static inline void ci_clock_time_get(ci_clock_time_t *t)
{
    QueryPerformanceCounter(t);
}

static inline void ci_clock_time_add(ci_clock_time_t *dst, const ci_clock_time_t *t1, const ci_clock_time_t *t2) {
    (*dst).QuadPart = (*t1).QuadPart + (*t2).QuadPart;
}

static inline void ci_clock_time_add_to(ci_clock_time_t *dst, const ci_clock_time_t *t1) {
    (*dst).QuadPart += (*t1).QuadPart;
}

static inline void ci_clock_time_sub(ci_clock_time_t *dst, const ci_clock_time_t *t1, const ci_clock_time_t *t2) {
    (*dst).QuadPart = (*t1).QuadPart - (*t2).QuadPart;
}

#endif

#ifdef __cplusplus
}
#endif

#endif
