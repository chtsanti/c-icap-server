#include "common.h"
#include "cfg_param.h"
#include "ci_threads.h"
#include "mem.h"
#include "debug.h"
#include "client.h"
#include "proc_mutex.h"
#include "shared_mem.h"
#if !defined(_WIN32)
#include <sys/wait.h>
#endif

int LOOPS = 10000;
int PROCS = 50;
int THREADS = 1;
int USE_DEBUG_LEVEL = -1;
int EMULATE_CRASHES = 0;
#if defined(_WIN32)
const char *SCHEME = "win32";
#else
const char *SCHEME = "pthread";
#endif

static struct ci_options_entry options[] = {
    {
        "-d", "debug_level", &USE_DEBUG_LEVEL, ci_cfg_set_int,
        "The debug level"
    },
    {
        "-s", "locking_scheme", &SCHEME, ci_cfg_set_str,
#if defined(_WIN32)
        "win32"
#else
        "posix|sysv|file"
#if defined(__CYGWIN__)
        "|win32"
#endif
#endif
    },
    {
        "-l", "loops", &LOOPS, ci_cfg_set_int,
        "The number of loops per thread (default is 10000)"
    },
    {
        "-p", "processes", &PROCS, ci_cfg_set_int,
        "The number of children to start (default is 50)"
    },
    {
        "-t", "threads", &THREADS, ci_cfg_set_int,
        "The number of threads per process to start (default is 1)"
    },
    {
        "-c", NULL, &EMULATE_CRASHES, ci_cfg_enable,
        "Emulate crashes on children processes"
    },
    {NULL,NULL,NULL,NULL,NULL}

};

void log_errors(void *unused, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

ci_proc_mutex_t stats_mutex;
ci_shared_mem_id_t sid;
struct stats {
    uint64_t c;
    int times[];
};
struct stats *Stats = NULL;
int KidId = -1;
ci_thread_mutex_t mtx;
ci_thread_cond_t cnd;
int Started = 0;

void thread()
{
    int i;
    ci_clock_time_t start, stop;
    if (THREADS > 1) {
        /*Wait to synchronize*/
        ci_thread_mutex_lock(&mtx);
        Started++;
        ci_thread_cond_wait(&cnd, &mtx);
        ci_thread_mutex_unlock(&mtx);
    }
    ci_clock_time_get(&start);
    for(i = 0; i < LOOPS; ++i) {
        assert(ci_proc_mutex_lock(&stats_mutex));
        Stats->c += 1;
        if (EMULATE_CRASHES) {
            /*Some kids will be crashed leaving locked the mutex to
              check recovery after crash.
             */
            if ((KidId == (PROCS * 0.25) && i > (LOOPS * 0.25)) ||
                (KidId == (PROCS * 0.5) && i > (LOOPS * 0.5)) ||
                (KidId == (PROCS * 0.75) && i > (LOOPS *0.75))) {
                ci_debug_printf(1, "Crashing kid %d at loop step %d\n", KidId, i);
                assert(0);
            }

        }
        ci_proc_mutex_unlock(&stats_mutex);
    }
    ci_clock_time_get(&stop);
    ci_thread_mutex_lock(&mtx);
    Stats->times[KidId] += ci_clock_time_diff_micro(&stop, &start);
    ci_thread_mutex_unlock(&mtx);
}

void run_child(int id) {
    KidId = id;
    ci_debug_printf(3, "Start kid %d\n", id);
    Stats = ci_shared_mem_attach(&sid);
    if (!Stats) {
        ci_debug_printf(1, "Error attaching memory block at %s\n", sid.name);
        return;
    }
    ci_debug_printf(2, "The kid %d will write to shared mem: %s\n", KidId, sid.name);
    Stats->times[KidId] = 0;
    ci_thread_mutex_init(&mtx);
    ci_thread_cond_init(&cnd);
    if (THREADS <= 1)
        thread();
    else {
        ci_thread_t *threads;
        int i;
        threads = malloc(sizeof(ci_thread_t) * THREADS);
        for (i = 0; i < THREADS; i++)  threads[i] = 0;
        for (i = 0; i < THREADS; i++) {
            ci_debug_printf(8, "Thread %d started\n", i);
            ci_thread_create(&(threads[i]),
                             (void *(*)(void *)) thread,
                             (void *) NULL /*data*/);
        }
        while(Started < THREADS) usleep(100);
        usleep(1000000);
        ci_thread_cond_broadcast(&cnd);
        for (i = 0; i < THREADS; i++) {
            ci_thread_join(threads[i]);
            ci_debug_printf(6, "Thread %d exited\n", i);
        }
    }
    ci_debug_printf(2, "Loops took %d microsecs\n", Stats->times[id]);
    ci_thread_mutex_destroy(&mtx);
    ci_thread_cond_destroy(&cnd);
    ci_shared_mem_detach(&sid);
}

#if defined(_WIN32)
typedef PROCESS_INFORMATION _PINFO;
#else
typedef pid_t _PINFO;
#endif

int ISKID = 0;
void _BUILD_KID(int id, _PINFO *pi, int argc, char *argv[])
{
#if defined(_WIN32)
    int bytes, i;
    char _CMD[2048];
    bytes = snprintf(_CMD, sizeof(_CMD), "%s --kid %d", argv[0], id);
    for(i = 1; i < argc && bytes < sizeof(_CMD); ++i) {
        bytes += snprintf(_CMD + bytes, sizeof(_CMD) - bytes, " %s", argv[i]);
    }
    ci_debug_printf(3, "Run kid command: %s\n", _CMD);
    assert(bytes < sizeof(_CMD));
    STARTUPINFO si;
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( pi, sizeof(_PINFO) );
    /* Start the child process.*/
    if(!CreateProcess(NULL, _CMD, NULL, NULL, FALSE, 0, NULL, NULL, &si, pi )) {
        ci_debug_printf(1, "CreateProcess failed (%d).\n", GetLastError());
        pi->hProcess = NULL;
        pi->hThread  = NULL;
    }
    ci_debug_printf(3, "OK process created\n");
#else
    if ((*pi = fork()) == 0) {
        ISKID = 1;
        KidId = id;
    }
#endif
}

void _WAIT_KID(_PINFO *pi)
{
#if defined(_WIN32)
    WaitForSingleObject(pi->hProcess, INFINITE );
    CloseHandle(pi->hProcess );
    CloseHandle(pi->hThread );
    ci_debug_printf(3, "child %p terminated\n", pi->hProcess);
#else
    int pid, status;
    // just wait for any kid;
    pid = wait(&status);
    if (!WIFEXITED(status)) {
        ci_debug_printf(1, "Child %d abnormal termination with status %d\nCheck mutex states\n", pid, status);
        ci_proc_mutex_recover_after_crash();
    } else {
        ci_debug_printf(4, "Child %d terminated with status %d\n", pid, status);
../    }
#endif
}

int main(int argc, char *argv[])
{
    CI_DEBUG_STDOUT = 1;
#if defined(_WIN32)
    if (argc > 2 && strcmp(argv[1], "--kid") == 0) {
        ISKID = 1;
        KidId = atoi(argv[2]);
        argv += 2;
        argc -= 2;
    }
#endif
    ci_client_library_init();
    __log_error = (void (*)(void *, const char *, ...)) log_errors;     /*set c-icap library log  function */

    if (!ci_args_apply(argc, argv, options)) {
        ci_args_usage(argv[0], options);
        exit(-1);
    }
    if (USE_DEBUG_LEVEL >= 0)
        CI_DEBUG_LEVEL = USE_DEBUG_LEVEL;

    if (!ci_proc_mutex_set_scheme(SCHEME)) {
        ci_debug_printf(1, "Wrong locking scheme: %s\n", SCHEME);
        exit(-1);
    }

    void *mem = ci_shared_mem_create(&sid, "test_shared_locking", sizeof(struct stats) + PROCS * sizeof(int));
    if (!mem) {
        ci_debug_printf(1, "Can not create shared memory\n");
        exit(-1);
    }
    ci_proc_mutex_init(&stats_mutex, "stats");
    int i;
    _PINFO *processes = calloc(PROCS, sizeof(_PINFO));
    for(i = 0; i < PROCS && !ISKID; i++) {
        _BUILD_KID(i, &processes[i], argc, argv);
    }

    if (ISKID) {
        ci_debug_printf(4, "Run runchild\n");
        run_child(KidId);
        exit(0);
    }

    for(i = 0; i < PROCS; i++) {
        if (processes[i].hProcess != NULL)
            _WAIT_KID(&processes[i]);
    }

    ci_proc_mutex_destroy(&stats_mutex);
    struct stats *stats = mem;
    uint64_t allTime = 0;
    for (i = 0; i < PROCS; ++i)
        allTime += stats->times[i];
    printf("Scheme: %s\n"
           "Loops: %"PRIu64"\n"
           "PROCESSES: %d\n"
           "Mean time (microsecs): %"PRIu64"\n"
           "Processes mean time (microsecs): %"PRIu64"\n"
           "Sum time (microsecs): %"PRIu64"\n",
           SCHEME,
           stats->c,
           PROCS,
           (stats->c ? allTime/stats->c : 0),
           (PROCS ? allTime/PROCS : 0),
           allTime
        );

    ci_shared_mem_destroy(&sid);
    return 0;
}
