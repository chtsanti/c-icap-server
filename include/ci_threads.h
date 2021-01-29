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


#ifndef __C_ICAP_CI_THREADS_H
#define __C_ICAP_CI_THREADS_H

#include "c-icap.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _WIN32

#include <pthread.h>

typedef pthread_mutex_t ci_thread_mutex_t;
typedef pthread_cond_t ci_thread_cond_t;
typedef pthread_t ci_thread_t;

CI_DECLARE_FUNC(int) ci_thread_mutex_init(ci_thread_mutex_t *pmutex);
CI_DECLARE_FUNC(int) ci_thread_mutex_destroy(ci_thread_mutex_t *pmutex);

static inline int ci_thread_mutex_lock(ci_thread_mutex_t *mtx) {
    return pthread_mutex_lock(mtx);
}

static inline int ci_thread_mutex_unlock(ci_thread_mutex_t *mtx) {
    return pthread_mutex_unlock(mtx);
}

static inline ci_thread_t ci_thread_self() {
    return pthread_self();
}

#ifdef USE_PTHREADS_RWLOCK

typedef pthread_rwlock_t ci_thread_rwlock_t;

CI_DECLARE_FUNC(int) ci_thread_rwlock_init(ci_thread_rwlock_t *);
CI_DECLARE_FUNC(int) ci_thread_rwlock_destroy(ci_thread_rwlock_t *);

static inline int ci_thread_rwlock_rdlock(ci_thread_rwlock_t *rwlock) {
    return pthread_rwlock_rdlock(rwlock);
}

static inline int ci_thread_rwlock_wrlock(ci_thread_rwlock_t *rwlock) {
    return pthread_rwlock_wrlock(rwlock);
}

static inline int ci_thread_rwlock_unlock(ci_thread_rwlock_t *rwlock) {
    return pthread_rwlock_unlock(rwlock);
}

#else

/*Someone can implement a better solution here using a mutex and a cond
  object to simulate rwlocks.
*/
typedef pthread_mutex_t ci_thread_rwlock_t;

static inline int ci_thread_rwlock_init(ci_thread_rwlock_t * rwlock) {
    return ci_thread_mutex_init(rwlock);
}

static inline int ci_thread_rwlock_destroy(ci_thread_rwlock_t * rwlock) {
    return ci_thread_mutex_destroy(rwlock);
}

static inline int ci_thread_rwlock_rdlock(ci_thread_rwlock_t * rwlock) {
    return ci_thread_mutex_lock(rwlock);
}

static inline int ci_thread_rwlock_wrlock(ci_thread_rwlock_t * rwlock) {
    return ci_thread_mutex_lock(rwlock);
}

static inline int ci_thread_rwlock_unlock(ci_thread_rwlock_t * rwlock) {
    return ci_thread_mutex_unlock(rwlock);
}

#endif

CI_DECLARE_FUNC(int) ci_thread_cond_init(ci_thread_cond_t *pcond);
CI_DECLARE_FUNC(int) ci_thread_cond_destroy(ci_thread_cond_t *pcond);

static inline int ci_thread_cond_wait(ci_thread_cond_t *pcond, ci_thread_mutex_t *pmtx) {
    /*The pthread_cond_Wait can be interrupted by a signal.
      This is a desired behavior in many cases, but also in other
      cases the operation should repeated after a such abort.
      As this is implemented, the caller should handle signal aborts.
     */
    return pthread_cond_wait(pcond, pmtx);
}

static inline int ci_thread_cond_broadcast(ci_thread_cond_t *pcond) {
    return pthread_cond_broadcast(pcond);
}

static inline int ci_thread_cond_signal(ci_thread_cond_t *pcond) {
    return pthread_cond_signal(pcond);
}

CI_DECLARE_FUNC(int) ci_thread_create(ci_thread_t *pthread_id, void *(*pfunc)(void *), void *parg);
CI_DECLARE_FUNC(int) ci_thread_join(ci_thread_t thread_id);

#else /*ifdef _WIN32*/

#include <windows.h>
#include <synchapi.h>

typedef  CRITICAL_SECTION ci_thread_mutex_t;
typedef  CRITICAL_SECTION ci_thread_rwlock_t; /*TODO: Replace with PSRWLOCK*/
#if 1
typedef CONDITION_VARIABLE ci_thread_cond_t;
#else
typedef  HANDLE ci_thread_cond_t;
#endif
typedef HANDLE  ci_thread_t;

CI_DECLARE_FUNC(int)  ci_thread_mutex_init(ci_thread_mutex_t *pmutex);
CI_DECLARE_FUNC(int) ci_thread_mutex_destroy(ci_thread_mutex_t *pmutex);

static inline int ci_thread_mutex_lock(ci_thread_mutex_t * pmutex)
{
    EnterCriticalSection(pmutex);
    return 0;
}

static inline int ci_thread_mutex_unlock(ci_thread_mutex_t * pmutex)
{
    LeaveCriticalSection(pmutex);
    return 0;
}

CI_DECLARE_FUNC(int) ci_thread_rwlock_init(ci_thread_rwlock_t *);
CI_DECLARE_FUNC(int) ci_thread_rwlock_destroy(ci_thread_rwlock_t *);

static inline int ci_thread_rwlock_rdlock(ci_thread_rwlock_t * rwlock)
{
    EnterCriticalSection(rwlock);
    return 0;
}

static inline int ci_thread_rwlock_wrlock(ci_thread_rwlock_t * rwlock)
{
    EnterCriticalSection(rwlock);
    return 0;
}

static inline int ci_thread_rwlock_unlock(ci_thread_rwlock_t * rwlock)
{
    LeaveCriticalSection(rwlock);
    return 0;
}

CI_DECLARE_FUNC(int)  ci_thread_cond_init(ci_thread_cond_t *pcond);
CI_DECLARE_FUNC(int) ci_thread_cond_destroy(ci_thread_cond_t *pcond);

static inline int ci_thread_cond_wait(ci_thread_cond_t * pcond, ci_thread_mutex_t * pmutex)
{
#if 1
    SleepConditionVariableCS(pcond, pmutex, INFINITE);
#else
    ci_thread_mutex_unlock(pmutex);
    WaitForSingleObject(*pcond, INFINITE);
    ci_thread_mutex_lock(pmutex);
#endif
    return 0;
}

static inline int ci_thread_cond_broadcast(ci_thread_cond_t * pcond)
{
#if 1
    WakeAllConditionVariable(pcond);
#else
    SetEvent(*pcond);  /* This does not work with autoreset events */
#endif
    return 0;
}

static inline int ci_thread_cond_signal(ci_thread_cond_t * pcond)
{
#if 1
    WakeConditionVariable(pcond);
#else
    SetEvent(*pcond);
#endif
    return 0;
}

CI_DECLARE_FUNC(int) ci_thread_create(ci_thread_t *thread_id, void *(*pfunc)(void *), void *parg);
CI_DECLARE_FUNC(int) ci_thread_join(ci_thread_t thread_id);
CI_DECLARE_FUNC(ci_thread_t) ci_thread_self();

#endif

#ifdef __cplusplus
}
#endif

#endif /*__C_ICAP_CI_THREADS_H */
