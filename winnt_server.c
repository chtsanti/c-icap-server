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
#include <stdio.h>
#include "commands.h"
#include "net_io.h"
#ifdef USE_OPENSSL
#include "net_io_ssl.h"
#endif
#include "proc_mutex.h"
#include "debug.h"
#include "log.h"
#include "request.h"
#include "ci_threads.h"
#include "proc_threads_queues.h"
#include "cfg_param.h"
#include "port.h"
#include "server.h"
#include <tchar.h>

//#define MULTICHILD
#undef MULTICHILD

typedef struct server_decl {
    int srv_id;
    ci_thread_t srv_pthread;
    struct connections_queue *con_queue;
    ci_request_t *current_req;
    int served_requests;
    int served_requests_no_reallocation;
    int running;
} server_decl_t;

ci_thread_mutex_t threads_list_mtx;
server_decl_t **threads_list = NULL;

ci_thread_cond_t free_server_cond;
ci_thread_mutex_t counters_mtx;

struct childs_queue *childs_queue = NULL;
child_shared_data_t *child_data;
struct connections_queue *con_queue;
DWORD MY_PROC_PID = 0;
static ci_stat_memblock_t *STATS = NULL;
int CHILD_HALT = 0;

/*Interprocess accepting mutex ....*/
ci_proc_mutex_t accept_mutex;

ci_thread_t listener;
TCHAR *C_ICAP_CMD = TEXT("c-icap.exe -c");

extern int KEEPALIVE_TIMEOUT;
extern int MAX_SECS_TO_LINGER;
extern int MAX_REQUESTS_BEFORE_REALLOCATE_MEM;
extern struct ci_server_conf CI_CONF;

#define hard_close_connection(connection)  ci_hard_close(connection->fd)
#define close_connection(connection) ci_linger_close(connection->fd,MAX_SECS_TO_LINGER)
#define check_for_keepalive_data(fd) ci_wait_for_data(fd,KEEPALIVE_TIMEOUT,wait_for_read)

/*Main proccess variables*/
int c_icap_going_to_term = 0;
int c_icap_reconfigure = 0;

void init_commands();

static void exit_normaly()
{
    int i = 0;
    server_decl_t *srv;
    ci_debug_printf(1, "Suppose that all children have already exited...\n");
    while ((srv = threads_list[i]) != NULL) {
        if (srv->current_req) {
            close_connection(srv->current_req->connection);
            ci_request_destroy(srv->current_req);
        }
        free(srv);
        threads_list[i] = NULL;
        i++;
    }
    free(threads_list);
    dettach_childs_queue(childs_queue);
    log_close();
}


static void cancel_all_threads()
{
    int i = 0;
//     ci_thread_mutex_lock(&threads_list_mtx);

    ci_thread_cond_broadcast(&(con_queue->queue_cond));        //What about childs that serve a request?
    while (threads_list[i] != NULL) {
        ci_debug_printf(1, "Cancel server %d, thread_id %d (%d)\n",
                        threads_list[i]->srv_id, threads_list[i]->srv_pthread,
                        i);
        ci_thread_join(threads_list[i]->srv_pthread);
        i++;
    }
//     ci_threadmutex_unlock(&threads_list_mtx);
}

server_decl_t *newthread(struct connections_queue *con_queue)
{
    server_decl_t *serv;
    serv = (server_decl_t *) malloc(sizeof(server_decl_t));
    serv->srv_id = 0;
    serv->con_queue = con_queue;
    serv->served_requests = 0;
    serv->served_requests_no_reallocation = 0;
    serv->current_req = NULL;
    serv->running = 1;

    return serv;
}




int thread_main(server_decl_t * srv)
{
    struct connections_queue_item con;
    char clientname[CI_MAXHOSTNAMELEN + 1];
    int ret, request_status = 0;

//***********************
//     thread_signals();
//*************************
    //    srv->srv_id = getpid(); //Setting my pid ...
    srv->srv_pthread = ci_thread_self();
    for (;;) {
        if (child_data->to_be_killed) {
            ci_debug_printf(3, "Thread exiting.....\n");
            srv->running = 0;
            return 1;        //Exiting thread.....
        }

        if ((ret = get_from_queue(con_queue, &con)) == 0) {
            if (child_data->to_be_killed) {
                srv->running = 0;
                return 1;
            }
            ret = wait_for_queue(con_queue);
            if (ret >= 0)
                continue;
        }

        if (ret < 0) {        //An error has occured
            ci_debug_printf(1, "Error getting from connections queue\n");
            break;
        }

        ci_atomic_add_i32(&(child_data->usedservers), 1);
        ci_connection_set_nonblock(&con.conn);
        ret = 1;
        if (srv->current_req == NULL) {
            srv->current_req = server_request_alloc();
            if (!srv->current_req) {
                ci_debug_printf(1, "ERROR: Request memory allocation failure, reject connection\n");
                ci_connection_hard_close(&con.conn);
                /* Does it make sense to continue if we can not allocate a small amount of memory? */
                goto end_of_main_loop_thread;
            }
        }

        ret = server_request_use_connection(srv->current_req, &con.conn, con.proto);
        if (ret == 0) {
            /*The request rejected. Log an error and continue*/
            ci_sockaddr_t_to_host(&(con.conn.claddr), clientname,
                                  CI_MAXHOSTNAMELEN);
            ci_debug_printf(1, "Request from %s is denied\n", clientname);
            ci_connection_hard_close(&con.conn);
            goto end_of_main_loop_thread;
        }
        
        do {
            if ((request_status = process_request(srv->current_req)) == CI_NO_STATUS) {
                ci_debug_printf(1,
                                "Process request timeout or interupted....\n");
                break;      //
            }

            srv->served_requests++;
            srv->served_requests_no_reallocation++;

            ci_atomic_add_i64(&child_data->requests, 1);

            log_access(srv->current_req, request_status);
//             break; //No keep-alive ......

            if (child_data->to_be_killed)
                return 1;   //Exiting thread.....

            ci_debug_printf(1, "Keep-alive:%d\n",
                            srv->current_req->keepalive);
            if (srv->current_req->keepalive
                    && check_for_keepalive_data(srv->current_req->connection->
                                                fd) > 0) {
                ci_request_reset(srv->current_req);
                ci_debug_printf(1,
                                "Server %d going to serve new request from client (keep-alive) \n",
                                srv->srv_id);
            } else
                break;
        } while (1);

        if (srv->current_req) {
            if (request_status != CI_OK || child_data->to_be_killed)
                ci_connection_hard_close(srv->current_req->connection);
            else
                ci_connection_linger_close(srv->current_req->connection,MAX_SECS_TO_LINGER);
        }
        if (srv->served_requests_no_reallocation >
                MAX_REQUESTS_BEFORE_REALLOCATE_MEM) {
            ci_debug_printf(1,
                            "Max requests reached, reallocate memory and buffers .....\n");
            ci_request_destroy(srv->current_req);
            srv->current_req = NULL;
            srv->served_requests_no_reallocation = 0;
        }

end_of_main_loop_thread:
        ci_atomic_sub_i32(&child_data->usedservers, 1);
        ci_thread_cond_signal(&free_server_cond);
    }
    srv->running = 0;
    return 1;
}

/*TODO: Reuse of sockets created during this function.
To do this, call of DiconnectEx function needed instead of closesocket function
and AcceptEx and overlapped operations must used.
The connections queue needs a small redesign
maybe with lists instead of connections array....*/

int listener_main(void *unused)
{
    struct connections_queue_item con;
    int haschild = 1, jobs_in_queue = 0;
    int32_t child_usedservers;
    int64_t pid = 0;

    for (;;) {
#ifdef MULTICHILD
        //Global for
        if (!ci_proc_mutex_lock(&accept_mutex)) {
            if (child_data->to_be_killed)
                return 1;
            continue;
        }
#endif
        if (child_data->to_be_killed)
            return 1;
        child_data->idle = 0;
        pid = (int64_t) child_data->pid;
        ci_debug_printf(1, "Child %d getting requests now ...\n", pid);

        do {                  //Getting requests while we have free servers.....
            int i, ret;
            int max_fd = 0;
            ci_port_t *port;
            struct timeval tv = {1, 0};
            fd_set fds;
            FD_ZERO(&fds);
            for (i = 0; (port = (ci_port_t *)ci_vector_get(CI_CONF.PORTS, i)) != NULL; ++i) {
                if (port->accept_socket > max_fd) max_fd = port->accept_socket;
                FD_SET(port->accept_socket, &fds);
            }

            ret = select(max_fd + 1, &fds, NULL, NULL, &tv);
            if (ret < 0) {
                char errMsg[256];
                ci_debug_printf(1, "Error in select/accept : %s\n", ci_str_last_network_error(errMsg, sizeof(errMsg)));
                goto LISTENER_FAILS;
            }
            if (child_data->to_be_killed) {
                ci_debug_printf(5,
                                "Listener server signalled to exit!\n");
                goto LISTENER_FAILS;
            }
            if (ret == 0)
                continue;
            for (i = 0; (port = (ci_port_t *)ci_vector_get(CI_CONF.PORTS, i)) != NULL; ++i) {
                if (!FD_ISSET(port->accept_socket, &fds))
                    continue;
                ret = 0;
                do {
                    ci_connection_reset(&con.conn);
#ifdef USE_OPENSSL
                    if (port->tls_accept_details)
                        ret = icap_accept_tls_connection(port, &con.conn);
                    else
#endif
                        ret = icap_accept_raw_connection(port, &con.conn);
                    if (ret <= 0) {
                        if (child_data->to_be_killed) {
                            ci_debug_printf(5, "Accept aborted: listener server signalled to exit!\n");
                            goto LISTENER_FAILS;
                        } else if (ret == -2) {
                            ci_debug_printf(1, "Fatal error while accepting!\n");
                            goto LISTENER_FAILS;
                        } /*else ret is -1 for aborted, or zero for EINTR*/
                    }
                } while (ret == 0);

                // Probably ECONNABORTED or similar error
                if (!ci_socket_valid(con.conn.fd))
                    continue;

                icap_socket_opts(con.conn.fd, MAX_SECS_TO_LINGER);

                if ((jobs_in_queue = put_to_queue(con_queue, &con)) == 0) {
                    ci_debug_printf(1,
                                    "Jobs in Queue: %d, Free servers: %d, Used Servers: %d, Requests: %d\n",
                                    jobs_in_queue, child_data->servers - child_data->usedservers,
                                    child_data->usedservers,
                                    child_data->requests);
                    ci_connection_hard_close(&con.conn);
                    continue;
                }
                //STAT_INT64_INC(STATS, port->stat_connections, 1);
            } // for CI_CONF.PORTS[i]...

            if (child_data->to_be_killed) {
                ci_debug_printf(5, "Listener server must exit!\n");
                goto LISTENER_FAILS;
            }
            ci_atomic_load_i32(&child_data->usedservers, &child_usedservers);
            haschild = ((child_data->servers - child_usedservers) > 0 ? 1 : 0);
        } while (haschild);

#ifdef MULTICHILD
        child_data->idle = 1;
        ci_proc_mutex_unlock(&accept_mutex);
#endif
        ci_atomic_load_i32(&child_data->usedservers, &child_usedservers);

        if (child_data->servers - child_usedservers == 0) {
            ci_debug_printf(1,
                            "Child %d waiting for a thread to accept more connections ...\n",
                            pid);
            ci_thread_mutex_lock(&counters_mtx);
            ci_thread_cond_wait(&free_server_cond, &counters_mtx);
            ci_thread_mutex_unlock(&counters_mtx);
            Sleep(10);
        }

    }

LISTENER_FAILS:
#ifdef MULTICHILD
    while (!ci_proc_mutex_unlock(&accept_mutex)) {
        if (errno != EINTR) {
            ci_debug_printf(1,
                            "Error:%d while trying to unlock proc_mutex of server:%d\n",
                            errno, pid);
            break;
        }
        ci_debug_printf(7,
                        "Mutex lock interrupted while trying to unlock proc_mutex before terminating\n");
    }
#endif
    return 0;
}


void child_main()
{
    ci_thread_t thread;
    int i;
#ifdef MULTICHILD
    char op;
    DWORD dwRead;
#endif
    //   child_signals();
    MY_PROC_PID = GetCurrentProcessId();

#ifdef MULTICHILD
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if ((hStdin == INVALID_HANDLE_VALUE))
        ExitProcess(1);
#else
    init_commands();
    execute_commands_no_lock(CI_CMD_MONITOR_START);
#endif

    ci_thread_mutex_init(&threads_list_mtx);
    ci_thread_mutex_init(&counters_mtx);
    ci_thread_cond_init(&free_server_cond);

    int ret = ci_stat_attach_mem(child_data->stats, child_data->stats_size, NULL);
    assert(ret);
    STATS = ci_stat_memblock_get();

    commands_execute_start_child();

    threads_list =
        (server_decl_t **) malloc((CI_CONF.THREADS_PER_CHILD + 1) *
                                  sizeof(server_decl_t *));
    con_queue = init_queue(CI_CONF.THREADS_PER_CHILD);

    for (i = 0; i < CI_CONF.THREADS_PER_CHILD; i++) {
        if ((threads_list[i] = newthread(con_queue)) == NULL) {
            exit(-1);        // FATAL error.....
        }
        (void)ci_thread_create(&thread,
                               (void *(*)(void *)) thread_main,
                               (void *) threads_list[i]);
    }
    threads_list[CI_CONF.THREADS_PER_CHILD] = NULL;
    ci_debug_printf(1, "Threads created ....\n");
    (void)ci_thread_create(&listener, (void *(*)(void *)) listener_main, NULL);

//Listen for events from main server better..............
#ifdef MULTICHILD
    while (ReadFile(hStdin, &op, 1, &dwRead, NULL)) {
        printf("Operation Read: %c\n", op);
        if (op == 'q')
            goto end_child_main;
    }
#else
    while(c_icap_going_to_term == 0) {
        sleep(1);
        // waitforcommands
        // handle_child_process_commands(buf);
        // handle_main_process_commands(buf);
        commands_exec_scheduled(CI_CMD_ONDEMAND);
        commands_exec_scheduled(CI_CMD_MONITOR_ONDEMAND);
    }
    child_data->to_be_killed = GRACEFULLY;
#endif
    ci_thread_join(listener);

#ifdef MULTICHILD
end_child_main:
#endif
    cancel_all_threads();
    commands_execute_stop_child();
    exit_normaly();
}

#ifdef MULTICHILD

int create_child(PROCESS_INFORMATION * pi, HANDLE * pipe)
{
    STARTUPINFO si;
    SECURITY_ATTRIBUTES saAttr;
    HANDLE hChildStdinRd, hChildStdinWr, hChildStdinWrDup, hSaveStdin;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    ZeroMemory(pi, sizeof(PROCESS_INFORMATION));

// Set the bInheritHandle flag so pipe handles are inherited.
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;


// Save the handle to the current STDIN.

    hSaveStdin = GetStdHandle(STD_INPUT_HANDLE);

// Create a pipe for the child process's STDIN.

    if (!CreatePipe(&hChildStdinRd, &hChildStdinWr, &saAttr, 0)) {
        printf("Stdin pipe creation failed\n");
        return 0;
    }

// Set a read handle to the pipe to be STDIN.

    if (!SetStdHandle(STD_INPUT_HANDLE, hChildStdinRd)) {
        printf("Redirecting Stdin failed");
        return 0;
    }

// Duplicate the write handle to the pipe so it is not inherited.

    if (!DuplicateHandle(GetCurrentProcess(), hChildStdinWr, GetCurrentProcess(), &hChildStdinWrDup, 0, FALSE, // not inherited
                         DUPLICATE_SAME_ACCESS)) {
        ci_debug_printf(1, "DuplicateHandle failed");
        return 0;
    }
    CloseHandle(hChildStdinWr);
    *pipe = hChildStdinWrDup;

    ci_debug_printf(1, "Going to start a child...\n");
    // Start the child process.

    if (!CreateProcessW(NULL,  // No module name (use command line).
                        C_ICAP_CMD,    // Command line.
                        NULL,  // Process handle not inheritable.
                        NULL,  // Thread handle not inheritable.
                        TRUE,  // Set handle inheritance to TRUE.
                        0,     // No creation flags.
                        NULL,  // Use parent's environment block.
                        NULL,  // Use parent's starting directory.
                        &si,   // Pointer to STARTUPINFO structure.
                        pi)    // Pointer to PROCESS_INFORMATION structure.
       ) {
        ci_debug_printf(1, "CreateProcess failed. (error:%d)\n",
                        GetLastError());
        return 0;
    }

    if (!SetStdHandle(STD_INPUT_HANDLE, hSaveStdin))
        printf("Re-redirecting Stdin failed\n");
    ci_debug_printf(1, "OK created....\n");
    return 1;
}


int send_handles(DWORD child_ID,
                 HANDLE pipe,
                 HANDLE child_handle,
                 SOCKET sock_fd,
                 HANDLE accept_mtx,
                 HANDLE shmem_id, HANDLE shmem_mtx, int qsize)
{
    DWORD dwWritten;
    HANDLE dupmutex;
    HANDLE dupshmem, dupshmemmtx;
    WSAPROTOCOL_INFO sock_info;

    memset(&sock_info, 0, sizeof(sock_info));

    if (WSADuplicateSocket(sock_fd, child_ID, &sock_info) != 0) {
        ci_debug_printf(1, "Error socket duplicating:%d\n",
                        WSAGetLastError());
    }

    DuplicateHandle(GetCurrentProcess(),
                    accept_mtx,
                    child_handle, &dupmutex, SYNCHRONIZE, FALSE, 0);
    DuplicateHandle(GetCurrentProcess(),
                    shmem_id,
                    child_handle,
                    &dupshmem, SYNCHRONIZE, FALSE, DUPLICATE_SAME_ACCESS);

    DuplicateHandle(GetCurrentProcess(),
                    shmem_mtx,
                    child_handle,
                    &dupshmemmtx, SYNCHRONIZE, FALSE, DUPLICATE_SAME_ACCESS);

    if (!WriteFile(pipe, &child_handle, sizeof(HANDLE), &dwWritten, NULL) ||
            dwWritten != sizeof(HANDLE)) {
        ci_debug_printf(1, "Error sending handles\n");
        return 0;
    }

    if (!WriteFile(pipe, &pipe, sizeof(HANDLE), &dwWritten, NULL) ||
            dwWritten != sizeof(HANDLE)) {
        ci_debug_printf(1, "Error sending handles\n");
        return 0;
    }

    if (!WriteFile(pipe, &dupmutex, sizeof(HANDLE), &dwWritten, NULL) ||
            dwWritten != sizeof(HANDLE)) {
        ci_debug_printf(1, "Error sending handles\n");
        return 0;
    }
    if (!WriteFile(pipe, &dupshmem, sizeof(HANDLE), &dwWritten, NULL) ||
            dwWritten != sizeof(HANDLE)) {
        ci_debug_printf(1, "Error sending handles\n");
        return 0;
    }
    if (!WriteFile(pipe, &dupshmemmtx, sizeof(HANDLE), &dwWritten, NULL) ||
            dwWritten != sizeof(HANDLE)) {
        ci_debug_printf(1, "Error sending handles\n");
        return 0;
    }
    if (!WriteFile(pipe, &qsize, sizeof(int), &dwWritten, NULL) ||
            dwWritten != sizeof(int)) {
        ci_debug_printf(1, "Error sending handles\n");
        return 0;
    }
    if (!WriteFile
            (pipe, &sock_info, sizeof(WSAPROTOCOL_INFO), &dwWritten, NULL)
            || dwWritten != sizeof(WSAPROTOCOL_INFO)) {
        ci_debug_printf(1, "Error sending handles\n");
        return 0;
    }
//   snprintf(buf, sizeof(buf), "%d:%d:%d:%d:%d",child_handle,dupmutex,dupshmem,dupshmemmtx,qsize);
//   WriteFile(pipe, buf, strlen(buf)+1, &dwWritten, NULL);
    return 1;
}


HANDLE start_child(ci_socket fd)
{
    HANDLE child_pipe;
    PROCESS_INFORMATION pi;
    if (!create_child(&pi, &child_pipe))
        return 0;
    printf("For child %d Writing to pipe:%d\n", pi.hProcess, child_pipe);
    send_handles(pi.dwProcessId, child_pipe, pi.hProcess, fd, accept_mutex,
                 childs_queue->shmid, childs_queue->queue_mtx,
                 childs_queue->size);
    return pi.hProcess;
}


int do_child()
{
    HANDLE hStdin, child_handle, parent_pipe;
    DWORD dwRead;
    WSAPROTOCOL_INFO sock_info;
    ci_socket sock_fd;

    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if ((hStdin == INVALID_HANDLE_VALUE))
        ExitProcess(1);

//   ReadFile(hStdin, buf, 512, &dwRead, NULL);
//   printf("Reading \"%s\" from server\n",buf);

//   sscanf(buf,"%d:%d:%d:%d:%d",&child_handle,&accept_mutex,
//                          &(childs_queue.shmid),&(childs_queue.queue_mtx),
//        &(childs_queue.size));

    if (!ReadFile(hStdin, &child_handle, sizeof(HANDLE), &dwRead, NULL)
            || dwRead != sizeof(HANDLE)) {
        ci_debug_printf(1, "Error reading handles.....\n");
        exit(0);
    }

    if (!ReadFile(hStdin, &parent_pipe, sizeof(HANDLE), &dwRead, NULL)
            || dwRead != sizeof(HANDLE)) {
        ci_debug_printf(1, "Error reading handles.....\n");
        exit(0);
    }

    if (!ReadFile(hStdin, &accept_mutex, sizeof(HANDLE), &dwRead, NULL)
            || dwRead != sizeof(HANDLE)) {
        ci_debug_printf(1, "Error reading handles.....\n");
        exit(0);
    }
    if (!ReadFile(hStdin, &(childs_queue->shmid), sizeof(HANDLE), &dwRead, NULL)
            || dwRead != sizeof(HANDLE)) {
        ci_debug_printf(1, "Error reading handles.....\n");
        exit(0);
    }
    if (!ReadFile
            (hStdin, &(childs_queue->queue_mtx), sizeof(HANDLE), &dwRead, NULL)
            || dwRead != sizeof(HANDLE)) {
        ci_debug_printf(1, "Error reading handles.....\n");
        exit(0);
    }
    if (!ReadFile(hStdin, &(childs_queue->size), sizeof(int), &dwRead, NULL) ||
            dwRead != sizeof(int)) {
        ci_debug_printf(1, "Error reading handles.....\n");
        exit(0);
    }

    if (!ReadFile
            (hStdin, &(sock_info), sizeof(WSAPROTOCOL_INFO), &dwRead, NULL)
            || dwRead != sizeof(WSAPROTOCOL_INFO)) {
        ci_debug_printf(1, "Error reading handles.....\n");
        exit(0);
    }

    if ((sock_fd = WSASocket(FROM_PROTOCOL_INFO,
                             FROM_PROTOCOL_INFO,
                             FROM_PROTOCOL_INFO,
                             &(sock_info), 0, 0)) == INVALID_SOCKET) {
        ci_debug_printf(1, "Error in creating socket :%d\n",
                        WSAGetLastError());
        return 0;
    }


    if (!attach_childs_queue(childs_queue)) {
        ci_debug_printf(1, "Error in new child .....\n");
        return 0;
    }
    ci_debug_printf(1, "Shared memory attached....\n");
    child_data =
        register_child(childs_queue, GetCurrentProcessId(), CI_CONF.THREADS_PER_CHILD,
                       parent_pipe);
    ci_debug_printf(1, "child registered ....\n");

    child_main(sock_fd);
    exit(0);
}

#endif

int tell_child_to_die(HANDLE pipe)
{
    DWORD dwWritten;
    char op = 'q';
    if (!WriteFile(pipe, &op, 1, &dwWritten, NULL) || dwWritten != 1) {
        return 0;
    }
    return 1;
}

int tell_child_to_restart(HANDLE pipe)
{
    DWORD dwWritten;
    char op = 'r';
    if (!WriteFile(pipe, &op, 1, &dwWritten, NULL) || dwWritten != 1) {
        return 0;
    }
    return 1;
}


ci_thread_mutex_t control_process_mtx;

int wait_achild_to_die()
{
    DWORD i, count, ret;
    HANDLE child_handles[MAXIMUM_WAIT_OBJECTS];
    process_pid_t child_pids[MAXIMUM_WAIT_OBJECTS];
    child_shared_data_t *ach;
    while (1) {
        ci_thread_mutex_lock(&control_process_mtx);
        for (i = 0, count = 0; i < (DWORD) childs_queue->size && count < MAXIMUM_WAIT_OBJECTS; i++) {
            if (childs_queue->childs[i].pHandle != INVALID_HANDLE_VALUE) {
                child_pids[count] = childs_queue->childs[i].pid;
                child_handles[count++] = childs_queue->childs[i].pHandle;
            }
        }
        ci_thread_mutex_unlock(&control_process_mtx);
        if (count == 0) {
            Sleep(100);
            continue;
        }
        ret = WaitForMultipleObjects(count, child_handles, TRUE, INFINITE);
        if (ret == WAIT_TIMEOUT) {
            ci_debug_printf(1, "Wait failed. Bug: timeout but no timeout is set\n");
            continue;
        }
        if (ret == WAIT_FAILED) {
            ci_debug_printf(1, "Wait failed. Try again!!!!!!\n");
            continue;
        }
        if (ret >= WAIT_ABANDONED_0) {
            ci_debug_printf(1, "Wait failed. Bug: wrong object?\n");
            continue;
        }
        ci_thread_mutex_lock(&control_process_mtx);
        process_pid_t died_child = child_pids[ret];
        HANDLE died_child_handle = child_handles[ret];
        ci_debug_printf(1,
                        "Child with handle %d died, lets clean-up the queue\n",
                        (int)died_child);
        ach = get_child_data(childs_queue, died_child);
        CloseHandle(ach->pipe);
        remove_child(childs_queue, died_child, 0);
        CloseHandle(died_child_handle);
        ci_thread_mutex_unlock(&control_process_mtx);
    }
}


//int check_for_died_child(struct childs_queue *childs_queue){
int check_for_died_child(DWORD msecs)
{
    DWORD i, count, ret;
    HANDLE child_handles[MAXIMUM_WAIT_OBJECTS];
    process_pid_t child_pids[MAXIMUM_WAIT_OBJECTS];
    child_shared_data_t *ach;
    ci_thread_mutex_lock(&control_process_mtx);
    for (i = 0, count = 0; i < (DWORD) childs_queue->size && count < MAXIMUM_WAIT_OBJECTS; i++) {
        if (childs_queue->childs[i].pHandle != INVALID_HANDLE_VALUE) {
            child_pids[count] = childs_queue->childs[i].pid;
            child_handles[count++] = childs_queue->childs[i].pHandle;
        }
    }
    ci_thread_mutex_unlock(&control_process_mtx);
    if (count == 0) {
        ci_debug_printf(1, "Oups no children! waiting for a while.....\n!");
        Sleep(1000);
        return 0;
    }
    ci_debug_printf(1, "Objects :%d (max:%d)\n", count, MAXIMUM_WAIT_OBJECTS);
    ret = WaitForMultipleObjects(count, child_handles, FALSE, msecs);
    if (ret == WAIT_TIMEOUT) {
        ci_debug_printf(8, "Operation timeout, no died child....\n");
        return 0;
    }
    if (ret == WAIT_FAILED) {
        ci_debug_printf(2, "Wait failed. Try again!!!!!!\n");
        return 0;
    }

    if (ret >= WAIT_ABANDONED_0) {
        ci_debug_printf(1, "Wait failed. Bug: wrong object?\n");
        return 0;
    }
    process_pid_t died_child = child_pids[ret];
    HANDLE died_child_handle = child_handles[ret];
    ci_debug_printf(8, "Child with handle %d died, lets clean-up the queue\n",
                    died_child);
    ach = get_child_data(childs_queue, died_child);
    CloseHandle(ach->pipe);
    remove_child(childs_queue, died_child, 0);
    CloseHandle(died_child_handle);
    return 1;
}

int init_server()
{
    int i;
    ci_port_t *p;
    char buf[256];

    if (!CI_CONF.PORTS) {
        ci_debug_printf(1, "No ports configured!\n");
        return 0;
    }

#ifdef USE_OPENSSL
    if (CI_CONF.TLS_ENABLED) {
        ci_tls_init();
        ci_tls_set_passphrase_script(CI_CONF.TLS_PASSPHRASE);
    }
#endif

    for (i = 0; (p = (ci_port_t *)ci_vector_get(CI_CONF.PORTS, i)); ++i) {
        if (p->configured)
            continue;

#ifdef USE_OPENSSL
        if (p->tls_enabled) {
            if (!icap_init_server_tls(p))
                return 0;
        } else
#endif
            if (CI_SOCKET_INVALID == icap_init_server(p))
                return 0;

        snprintf(buf, sizeof(buf), "%s:%d%s connections", (p->address ? p->address : "localhost"), p->port, (p->tls_enabled ? ", TLS": ""));
        p->stat_connections = ci_stat_entry_register(buf, CI_STAT_INT64_T, "Server");
        p->configured = 1;
    }

    return 1;
}

void stop_command(const char *name, int type, const char **argv)
{
    c_icap_going_to_term = 1;
}

void reconfigure_command(const char *name, int type, const char **argv)
{
    if (type == MONITOR_PROC_CMD)
        c_icap_reconfigure = 1;
    //server_reconfigure();
}

void dump_statistics_command(const char *name, int type, const char **argv)
{
    if (type == MONITOR_PROC_CMD)
        dump_queue_statistics(childs_queue);
}

void test_command(const char *name, int type, const char **argv)
{
    int i = 0;
    ci_debug_printf(1, "Test command for %s. Arguments:",
                    (type ==
                     MONITOR_PROC_CMD ? "monitor process" : "child process"));
    while (argv[i] != NULL) {
        ci_debug_printf(1, "%s,", argv[i]);
        i++;
    }
    ci_debug_printf(1, "\n");
}

void init_commands()
{
    register_command("stop", MONITOR_PROC_CMD, stop_command);
    register_command("reconfigure", MONITOR_PROC_CMD, reconfigure_command);
    register_command("dump_statistics", MONITOR_PROC_CMD, dump_statistics_command);
    // register_command("test", MONITOR_PROC_CMD | CHILDS_PROC_CMD, test_command);
}

int start_server()
{

#ifdef MULTICHILD
    int child_indx, i;
    HANDLE child_handle;
    ci_thread_t mon_thread;
    int childs, freeservers, used;
    int64_t maxrequests;

    ci_proc_mutex_init(&accept_mutex);
    ci_thread_mutex_init(&control_process_mtx);

    if (CI_CONF.MAX_SERVERS > MAXIMUM_WAIT_OBJECTS)
        CI_CONF.MAX_SERVERS = MAXIMUM_WAIT_OBJECTS;

    if (!(childs_queue = create_childs_queue(CI_CONF.MAX_SERVERS))) {
        log_server(NULL, "Can't init shared memory.Fatal error, exiting!\n");
        ci_debug_printf(1,
                        "Can't init shared memory.Fatal error, exiting!\n");
        exit(0);
    }

    for (i = 0; i < CI_CONF.START_SERVERS + 2; i++) {
        child_handle = start_child();
    }

    /*Start died childs monitor thread*/
    /*     ci_thread_create(&mon_thread,
                  (void *(*)(void *))wait_achild_to_die,
                  (void *)NULL);
    */
    while (1) {
        if (check_for_died_child(5000))
            continue;
//        Sleep(5000);
        childs_queue_stats(childs_queue, &childs, &freeservers, &used,
                           &maxrequests);
        ci_debug_printf(1,
                        "Server stats: \n\t Children:%d\n\t Free servers:%d\n\tUsed servers:%d\n\tRequests served:%d\n",
                        childs, freeservers, used, maxrequests);

        if ((freeservers <= CI_CONF.MIN_SPARE_THREADS && childs < CI_CONF.MAX_SERVERS)
                || childs < CI_CONF.START_SERVERS) {
            ci_debug_printf(1, "Going to start a child .....\n");
            child_handle = start_child();
        } else if (freeservers >= CI_CONF.MAX_SPARE_THREADS && childs > CI_CONF.START_SERVERS) {
            ci_thread_mutex_lock(&control_process_mtx);
            if ((child_indx = find_an_idle_child(childs_queue)) < 0)
                continue;
            childs_queue->childs[child_indx].to_be_killed = GRACEFULLY;
            tell_child_to_die(childs_queue->childs[child_indx].pipe);
            ci_thread_mutex_unlock(&control_process_mtx);
            ci_debug_printf(1, "Going to stop child %d .....\n",
                            childs_queue->childs[child_indx].pid);
        }
    }
    /*
         for(i = 0; i<CI_CONF.START_SERVERS; i++){
          pid = wait(&status);
          ci_debug_printf(1,"The child %d died with status %d\n",pid,status);
         }
    */


#else
    childs_queue = malloc(sizeof(struct childs_queue));
    childs_queue->childs = (child_shared_data_t *) malloc(1 * sizeof(child_shared_data_t));
    childs_queue->size = 1;
    childs_queue->shared_mem_size = 0;
    childs_queue->stats_block_size = ci_stat_memblock_size();
    int MemBlobsCount = ci_server_shared_memblob_count();
    assert(MemBlobsCount >= 0);
    size_t stats_mem_size =
        childs_queue->stats_block_size + /*server stats*/
        childs_queue->stats_block_size + /*History stats*/
        sizeof(struct server_statistics) + MemBlobsCount * sizeof(ci_server_shared_blob_t);
    childs_queue->stats_area = malloc(stats_mem_size);
    childs_queue->stats_history = (childs_queue->stats_area + childs_queue->stats_block_size);
    ci_stat_memblock_init(childs_queue->stats_history, childs_queue->stats_block_size);

    childs_queue->srv_stats = (childs_queue->stats_area + 2 * childs_queue->stats_block_size);
    childs_queue->srv_stats->started_childs = 0;
    childs_queue->srv_stats->closed_childs = 0;
    childs_queue->srv_stats->crashed_childs = 0;
    childs_queue->srv_stats->blob_count = MemBlobsCount;

    assert(childs_queue->childs);
    childs_queue->childs[0].pid = GetCurrentProcessId();
    childs_queue->childs[0].pHandle = INVALID_HANDLE_VALUE;
    childs_queue->childs[0].servers = CI_CONF.THREADS_PER_CHILD;
    childs_queue->childs[0].usedservers = 0;
    childs_queue->childs[0].requests = 0;
    childs_queue->childs[0].to_be_killed = 0;
    childs_queue->childs[0].father_said = 0;
    childs_queue->childs[0].idle = 1;
    childs_queue->childs[0].stats_size = childs_queue->stats_block_size;
    childs_queue->childs[0].stats = childs_queue->stats_area;
    ci_stat_memblock_init(childs_queue->childs[0].stats, childs_queue->childs[0].stats_size);
    child_data = &(childs_queue->childs[0]);

    child_main();
#endif

    return 1;
}
