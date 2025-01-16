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

#include "common.h"
#include "c-icap.h"
#include "util.h"
#include "ci_time.h"

#include <time.h>
#include <assert.h>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include "ci_time.h"

LARGE_INTEGER _CI_CLOCK_FREQUENCY = {.QuadPart = 1};
struct _ci_TimeVal{
    uint64_t secs;
    uint64_t nsecs;
} _CI_CLOCK_EPOCH_BASE = {0, 0};
static LARGE_INTEGER _CI_PERFORMANCE_COUNTER_START = {.QuadPart = 0};

void ci_windows_util_init()
{
    QueryPerformanceFrequency(&_CI_CLOCK_FREQUENCY);
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    QueryPerformanceCounter(&_CI_PERFORMANCE_COUNTER_START);
    const uint64_t time100ns = (uint64_t)ft.dwLowDateTime + ((uint64_t)(ft.dwHighDateTime) << 32LL);
    const uint64_t epoch100ns = time100ns - 116444736000000000LL;
    _CI_CLOCK_EPOCH_BASE.secs = epoch100ns / 10000000;
    _CI_CLOCK_EPOCH_BASE.nsecs = (epoch100ns % 10000000) * 100;
}

void ci_performance_counter_to_epoch(LARGE_INTEGER *tm, uint64_t *secs, uint64_t *nsecs)
{
    assert(secs && nsecs);
    uint64_t counter_from_start = tm->QuadPart - _CI_PERFORMANCE_COUNTER_START.QuadPart;
    *secs = counter_from_start / _CI_CLOCK_FREQUENCY.QuadPart;
    uint64_t nsi = ((counter_from_start % _CI_CLOCK_FREQUENCY.QuadPart) * 1000000000LL) / _CI_CLOCK_FREQUENCY.QuadPart + _CI_CLOCK_EPOCH_BASE.nsecs;
    *nsecs = nsi % 1000000000LL;
    *secs += _CI_CLOCK_EPOCH_BASE.secs + nsi / 1000000000LL;
}

int strncasecmp(const char *s1, const char *s2, size_t n)
{
    int r = 0;
    while (n && ((s1 == s2)
                 || !(r = ((int) (tolower(*((unsigned char *) s1))))
                          - tolower(*((unsigned char *) s2)))) && (--n, ++s2,
                                  *s1++));
    return r;
}


int strcasecmp(const char *s1, const char *s2)
{
    int r = 0;
    while (((s1 == s2)
            || !(r =
                     ((int) (tolower(*((unsigned char *) s1)))) -
                     tolower(*((unsigned char *) s2)))) && (++s2, *s1++));
    return r;
}

char * ctime_r(const time_t *t, char *buf)
{
    errno_t err = ctime_s(buf, 26, t);
    if (err == 0)
        return buf;
    buf[0] = '\0';
    return NULL;
}

/*
  The following functions are safe because the localtime and gmtime are thread
  safe in Win32
*/
struct tm* localtime_r(const time_t *t, struct tm *tm)
{
    if (!t || !tm) return NULL;
    memcpy(tm, localtime(t), sizeof(struct tm));
    return tm;
}

struct tm* gmtime_r(const time_t *t, struct tm *tm)
{
    if (!t || !tm) return NULL;
    memcpy(tm, gmtime(t), sizeof(struct tm));
    return tm;
}

static const char *days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
                            };


static const char *months[] = {
    "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
    "Sep", "Oct", "Nov", "Dec"
};

void ci_strtime(char *buf)
{
    ci_strntime(buf, STR_TIME_SIZE);
}

void ci_strtime_rfc822(char *buf)
{
    ci_strntime_rfc822(buf, STR_TIME_SIZE);
}

void ci_strntime(char *buf, size_t size)
{
    assert(size > 0);
    SYSTEMTIME tm;
    GetLocalTime(&tm);
    snprintf(buf, size, "%s %s %d %d:%d:%d %d", days[tm.wDayOfWeek],
             months[tm.wMonth], tm.wDay, tm.wHour, tm.wMinute, tm.wSecond,
             tm.wYear);
}

//Untested code:
void ci_to_strntime(char *buf, size_t size, const time_t *tm)
{
    assert(size > 0);
    LONGLONG ll = (*tm * 10000000LL) + 116444736000000000LL;
    FILETIME ft;
    ft.dwLowDateTime = (DWORD) ll;
    ft.dwHighDateTime = ll >>32;
    SYSTEMTIME stm;
    FileTimeToSystemTime(&ft, &stm);
    snprintf(buf, size, "%s %s %d %d:%d:%d %d", days[stm.wDayOfWeek],
             months[stm.wMonth], stm.wDay, stm.wHour, stm.wMinute, stm.wSecond,
             stm.wYear);
}

void ci_strntime_rfc822(char *buf, size_t size)
{
    assert(size > 0);
    SYSTEMTIME tm;
    GetLocalTime(&tm);         /*Here we need GMT time not localtime! */
    snprintf(buf, size, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT",
             days[tm.wDayOfWeek], tm.wDay, months[tm.wMonth], tm.wYear,
             tm.wHour, tm.wMinute, tm.wSecond);
}

//Untested code:
void ci_to_strntime_rfc822(char *buf, size_t size, const time_t *tm)
{
    assert(size > 0);
    LONGLONG ll = (*tm * 10000000LL) + 116444736000000000LL;
    FILETIME ft;
    ft.dwLowDateTime = (DWORD) ll;
    ft.dwHighDateTime = ll >>32;
    SYSTEMTIME sysTm;
    FileTimeToSystemTime(&ft, &sysTm);
    snprintf(buf, size, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT",
             days[sysTm.wDayOfWeek], sysTm.wDay, months[sysTm.wMonth], sysTm.wYear,
             sysTm.wHour, sysTm.wMinute, sysTm.wSecond);
}

int ci_mktemp_file(char *dir, char *template, char *filename)
{
    int fd;
    GetTempFileName(dir, template, 1, filename);
    fd = open(filename, O_RDWR | O_CREAT | O_BINARY, _S_IREAD | _S_IWRITE);
    return fd;
}

char * ci_strerror(int error, char *buf, size_t buflen)
{
    if (strerror_s(buf, buflen, error) == 0) {
        return buf;
    } else {
	snprintf(buf, buflen, "%d", error);
	return buf;
    }
}

#ifndef offsetof
#define offsetof(type,field) ((int) ( (char *)&((type *)0)->field))
#endif                          /*  */
/*
static const unsigned char at_data[] = {
    'S', 'u', 'n', 'M', 'o', 'n', 'T', 'u', 'e', 'W', 'e', 'd',
    'T', 'h', 'u', 'F', 'r', 'i', 'S', 'a', 't',

    'J', 'a', 'n', 'F', 'e', 'b', 'M', 'a', 'r', 'A', 'p', 'r',
    'M', 'a', 'y', 'J', 'u', 'n', 'J', 'u', 'l', 'A', 'u', 'g',
    'S', 'e', 'p', 'O', 'c', 't', 'N', 'o', 'v', 'D', 'e', 'c',
    '?', '?', '?',
    ' ', '?', '?', '?',
    ' ', '0',
    offsetof(struct tm, tm_mday),
    ' ', '0',
    offsetof(struct tm, tm_hour),
    ':', '0',
    offsetof(struct tm, tm_min),
    ':', '0',
    offsetof(struct tm, tm_sec),
    ' ', '?', '?', '?', '?', '\n', 0
};
*/
/*
char *asctime_r(const struct tm *ptm, char *buffer)
{
    int tmp;
    assert(ptm);
    assert(buffer);
    memcpy(buffer, at_data + 3*(7 + 12), sizeof(at_data) - 3*(7 + 12));
    if (((unsigned int)(ptm->tm_wday)) <= 6) {
         memcpy(buffer, at_data + 3 * ptm->tm_wday, 3);
    }

    if (((unsigned int)(ptm->tm_mon)) <= 11) {
         memcpy(buffer + 4, at_data + 3*7 + 3 * ptm->tm_mon, 3);
    }

    buffer += 19;
    tmp = ptm->tm_year + 1900;
    if (((unsigned int) tmp) < 10000) {
         buffer += 4;
         do {
          *buffer = '0' + (tmp % 10);
          tmp /= 10;
         } while (*--buffer == '?');
    }

    do {
         --buffer;
         tmp = *((int *)(((const char *) ptm) + (int) *buffer));

         if (((unsigned int) tmp) >= 100) {
          buffer[-1] = *buffer = '?';
         } else
         {
          *buffer = '0' + (tmp % 10);

          buffer[-1] += (tmp/10);
         }
    } while ((buffer -= 2)[-2] == '0');

    if (*++buffer == '0') {
         *buffer = ' ';
    }

    return buffer - 8;
}
*/

int ci_screen_columns()
{
    CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_INPUT_HANDLE), &csbiInfo))
        return csbiInfo.dwSize.X;
    else
        return 80;
}
