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
#include "ci_threads.h"

int ci_thread_mutex_init(ci_thread_mutex_t * pmutex)
{
    InitializeCriticalSection(pmutex);
    return 0;
}

int ci_thread_mutex_destroy(ci_thread_mutex_t * pmutex)
{
    DeleteCriticalSection(pmutex);
    return 0;
}

int ci_thread_cond_init(ci_thread_cond_t * pcond)
{
#if 1
    InitializeConditionVariable(pcond);
#else
    *pcond = CreateEvent(NULL, FALSE, FALSE, NULL);
#endif
    return 0;
}

int ci_thread_cond_destroy(ci_thread_cond_t * pcond)
{
#if 1
    ;
#else
    CloseHandle(*pcond);
    *pcond = NULL;
#endif
    return 0;
}

int ci_thread_create(ci_thread_t * pthread_id, void *(*pfunc) (void *),
                     void *parg)
{
    *pthread_id =
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) pfunc, parg, 0, NULL);
    return 0;
}

int ci_thread_join(ci_thread_t thread_id)
{
    if (WaitForSingleObject(thread_id, INFINITE) == WAIT_FAILED) {
        return -1;
    }
    return 0;
}

ci_thread_t ci_thread_self()
{
    return GetCurrentThread();
}

/*Needs some work to implement a better solution here. At Vista there are a number of
related functions, but for Windows 2000/XP??
*/

int ci_thread_rwlock_init(ci_thread_rwlock_t * rwlock)
{
    InitializeCriticalSection(rwlock);
    return 0;
}

int ci_thread_rwlock_destroy(ci_thread_rwlock_t * rwlock)
{
    DeleteCriticalSection(rwlock);
    return 0;
}
