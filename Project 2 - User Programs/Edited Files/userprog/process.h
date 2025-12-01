#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"

/* Child process information kept in the parent. */
struct child_process
  {
    tid_t tid;                /* Thread id of the child. */
    int exit_status;          /* Exit status reported by the child. */
    bool exited;              /* True if the child has called exit(). */
    bool waited;              /* True if the parent has already waited. */

    /* Synchronization for exec() load status. */
    struct semaphore load_sema;   /* Parent waits on this until load finishes. */
    bool load_success;            /* True if load() succeeded in the child. */

    /* Synchronization for wait(). */
    struct semaphore wait_sema;   /* Parent waits on this until child exits. */

    struct list_elem elem;    /* List element for parent's children list. */
  };



tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
