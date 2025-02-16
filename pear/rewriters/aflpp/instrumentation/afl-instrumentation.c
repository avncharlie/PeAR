// This file is based upon "instrumentation/afl-compiler-rt.o.c" in the
// AFlPlusPlus project, commit: 7f17a94349830a54d2c899f56b149c0d7f9ffb9c

#include "include/config.h"
#include "include/types.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/shm.h>

#include <fcntl.h>

//#define _AFL_DOCUMENT_MUTATIONS 1

u8 *__afl_area_ptr_dummy;
extern u8 *__afl_area_ptr;
u32 __afl_debug;
u32 __afl_already_initialized_shm;
extern u32 __afl_prev_loc;

u32 __afl_already_initialized_forkserver;
u32 __afl_map_size = MAP_SIZE;
s32 child_pid;

void (*old_sigterm_handler)(int) = 0;
int        __afl_sharedmem_fuzzing __attribute__((weak)) = 0;
u32 __afl_connected = 0;
u8 is_persistent;

u8 first_pass = 1;
u32 cycle_cnt;

u32 *__afl_fuzz_len;
u8 *__afl_fuzz_ptr;

// new
uint32_t __document_mutation_counter = 0;

int __afl_persistent_loop(unsigned int max_cnt) {

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */
    memset(__afl_area_ptr, 0, __afl_map_size);
    __afl_area_ptr[0] = 1;
    __afl_prev_loc = 0;

    cycle_cnt = max_cnt;
    first_pass = 0;

    return 1;

  } else if (--cycle_cnt) {

    if (__afl_debug) {
        //fprintf(stderr, "DEBUG: going to stop child, cycle_cnt: %d\n", cycle_cnt);
    }

    raise(SIGSTOP);

    // Parent will have reset shared mem for us
    __afl_area_ptr[0] = 1;
    __afl_prev_loc = 0;

    return 1;

  } else {

    /* When exiting __AFL_LOOP(), make sure that the subsequent code that
        follows the loop is not traced. We do that by pivoting back to the
        dummy output region. */

    __afl_area_ptr = __afl_area_ptr_dummy;

    return 0;

  }

}

/* Report errors to forkserver controller */
void send_forkserver_error(int error) {
    u32 status;
    if (!error || error > 0xffff) return;
    status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
    if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) { return; }

}

/* Setup shared memory for bitmap */
void __afl_map_shm(void) {

    if (__afl_already_initialized_shm) return;
    __afl_already_initialized_shm = 1;

    char *id_str = getenv(SHM_ENV_VAR);

    if (__afl_debug) {
        fprintf(
            stderr,
            "DEBUG: (1) id_str %s, __afl_area_ptr %p, "
            "__afl_area_ptr_dummy %p, MAP_SIZE %u\n",
            id_str == NULL ? "<null>" : id_str, __afl_area_ptr,
            __afl_area_ptr_dummy, MAP_SIZE);
    }

    if (id_str) {
        u32 shm_id = atoi(id_str);
        __afl_area_ptr = (u8 *)shmat(shm_id, NULL, 0);

        /* Whooooops. */
        if (!__afl_area_ptr || __afl_area_ptr == (void *)-1) {
            send_forkserver_error(FS_ERROR_SHMAT);
            perror("shmat for map");
            _exit(1);
        }

        /* Write something into the bitmap so that even with low AFL_INST_RATIO,
           our parent doesn't give up on us. */
        __afl_area_ptr[0] = 1;

    } else {
        // no ID string = probably not running under parent, run as normal
        return;
    } 

    if (__afl_debug) {
        fprintf(
            stderr,
            "DEBUG: (2) id_str %s, __afl_area_ptr %p, "
            "__afl_area_ptr_dummy %p, MAP_SIZE %u\n",
            id_str == NULL ? "<null>" : id_str, __afl_area_ptr,
            __afl_area_ptr_dummy, MAP_SIZE);
    }

}

/* Set up AFL (will be called at start of program) */
void __afl_setup(void) {
    // Set up dummy map so program can still run until forkserver initialised
    __afl_area_ptr_dummy =  malloc(0x10000);

    if (__afl_area_ptr_dummy == NULL) {
        fprintf(stderr, "ERROR: malloc to setup dummy map failed\n");
        _exit(1);
    }

    __afl_area_ptr = __afl_area_ptr_dummy;

    if (getenv("AFL_DEBUG")) {
        __afl_debug = 1;
        fprintf(stderr, "DEBUG: debug enabled\n");
    } 

    // setup memory
    __afl_map_shm();
}

// ensure child is killed when forkserver exits
void __afl_at_exit(int signal) {
    //fprintf(stderr, "DEBUG: we gonna die!\n");
    if (child_pid > 0) {
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        child_pid = -1;
    }

    _exit(0);
}

void __afl_map_shm_fuzz() {
    char *id_str = getenv(SHM_FUZZ_ENV_VAR);
    if (__afl_debug) {
        fprintf(stderr, "DEBUG: fuzzcase shmem %s\n", id_str ? id_str : "none");
    }

    if (id_str) {
        u8 *map = NULL;
        u32 shm_id = atoi(id_str);
        map = (u8 *)shmat(shm_id, NULL, 0);

        /* Whooooops. */
        if (!map || map == (void *)-1) {
            perror("Could not access fuzzing shared memory");
            send_forkserver_error(FS_ERROR_SHM_OPEN);
            exit(1);
        }

        __afl_fuzz_len = (u32 *)map;
        __afl_fuzz_ptr = map + sizeof(u32);

        if (__afl_debug) {
            fprintf(stderr, "DEBUG: successfully got fuzzing shared memory\n");
        }

    } else {
        fprintf(stderr, "Error: variable for fuzzing shared memory is not set\n");
        send_forkserver_error(FS_ERROR_SHM_OPEN);
        exit(1);
    }

}

void __afl_start_forkserver(void) {

    if (__afl_already_initialized_forkserver) return;
    __afl_already_initialized_forkserver = 1;

    // Backup the original SIGTERM handler (restored by child on fork)
    // Then set at_exit function to be called on exit to tear down child
    struct sigaction orig_action;
    sigaction(SIGTERM, NULL, &orig_action);
    old_sigterm_handler = orig_action.sa_handler;
    signal(SIGTERM, __afl_at_exit);

    u8  tmp[4] = {0, 0, 0, 0};
    u32 status_for_fsrv = 0;
    u32 already_read_first = 0;
    u32 was_killed;

    u8 child_stopped = 0;

    // backup the original SIGCHILD (will be restored by child on fork) 
    // then reset handler to default
    void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

    // generate status to send to afl-fuzz
    if (__afl_map_size <= FS_OPT_MAX_MAPSIZE) {
        status_for_fsrv |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
    }
    if (__afl_sharedmem_fuzzing) { status_for_fsrv |= FS_OPT_SHDMEM_FUZZ; }
    if (status_for_fsrv) {
        status_for_fsrv |= (FS_OPT_ENABLED | FS_OPT_NEWCMPLOG);
    }
    memcpy(tmp, &status_for_fsrv, 4);

    /* Phone home and tell the parent that we're OK. If parent isn't there,
       assume we're not running in forkserver mode and just execute program. */
    if (write(FORKSRV_FD + 1, tmp, 4) != 4) { return; }

    __afl_connected = 1;

    if (__afl_sharedmem_fuzzing) {
        if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

        if (__afl_debug) {
            fprintf(stderr, "target forkserver recv: %08x\n", was_killed);
        }

        if ((was_killed & (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) ==
                (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) {
            // set up shared memory fuzzing
            __afl_map_shm_fuzz();
        }

        // Unsure why exactly this is needed when sharedmem fuzzing without
        // persistent mode (except that it won't work without it)
        // TODO: figure out
        if (is_persistent) {
            already_read_first = 1;
        }
    }

    // main forkserver loop
    while (1) {
        int status;

        /* Wait for parent by reading from the pipe. Abort if read fails. */
        if (already_read_first) {
            already_read_first = 0;
        } else {
            if (read(FORKSRV_FD, &was_killed, 4) != 4) {
                //fprintf(stderr, "ERROR: read from afl-fuzz\n");
                _exit(1);
            }
        }

#ifdef _AFL_DOCUMENT_MUTATIONS
        if (__afl_fuzz_ptr) {
            char            fn[32];
            sprintf(fn, "%09u:forkserver", __document_mutation_counter);
            s32 fd_doc = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
            if (fd_doc >= 0) {
                if (write(fd_doc, __afl_fuzz_ptr, *__afl_fuzz_len) != *__afl_fuzz_len) {
                    fprintf(stderr, "write of mutation file failed: %s\n", fn);
                    unlink(fn);
                }
                close(fd_doc);
            }
            __document_mutation_counter++;
        }
#endif

        /* If we stopped the child in persistent mode, but there was a race
           condition and afl-fuzz already issued SIGKILL, write off the old
           process. */
        if (child_stopped && was_killed) {
            child_stopped = 0;
            if (waitpid(child_pid, &status, 0) < 0) {
                fprintf(stderr, "ERROR: child_stopped && was_killed\n");
                _exit(1);
            }
        }

        if (!child_stopped) {
            /* Once woken up, create a clone of our process. */

            child_pid = fork();

            if (child_pid < 0) {
                fprintf(stderr, "ERROR: fork\n");
                _exit(1);
            }

            /* In child process: close fds, resume execution. */
            if (!child_pid) {
                signal(SIGCHLD, old_sigchld_handler);
                signal(SIGTERM, old_sigterm_handler);
                close(FORKSRV_FD);
                close(FORKSRV_FD + 1);
                return;
            }

        } else {
            /* Special handling for persistent mode: if the child is alive but
               currently stopped, simply restart it with SIGCONT. */
            kill(child_pid, SIGCONT);
            child_stopped = 0;
        }


        /* In parent process: write PID to pipe, then wait for child. */
        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
            fprintf(stderr, "ERROR: write to afl-fuzz\n");
            _exit(1);
        }

        if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0) {
            fprintf(stderr, "ERROR: waitpid\n");
            _exit(1);
        }

        //if (__afl_debug) {
        //    if (WIFEXITED(status)) {
        //        printf("DEBUG: Child process exited normally with status: %d\n", WEXITSTATUS(status));
        //    } else if (WIFSIGNALED(status)) {
        //        printf("DEBUG: Child process terminated by signal: %d\n", WTERMSIG(status));
        //    } else if (WIFSTOPPED(status)) {
        //        printf("DEBUG: Child process stopped by signal: %d\n", WSTOPSIG(status));
        //    } else if (WIFCONTINUED(status)) {
        //        printf("DEBUG: Child process resumed after being stopped.\n");
        //    }
        //}

        /* In persistent mode, the child stops itself with SIGSTOP to indicate
           a successful run. In this case, we want to wake it up without forking
           again. */
        if (WIFSTOPPED(status)) child_stopped = 1;

        //if (__afl_debug) {
        //    fprintf(stderr, "DEBUG: child_stopped: %d\n", child_stopped);
        //}

        /* Relay wait status to pipe, then loop back. */
        if (write(FORKSRV_FD + 1, &status, 4) != 4) {
            fprintf(stderr, "ERROR: writing to afl-fuzz\n");
            _exit(1);
        }
    }
}
