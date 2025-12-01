#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

#include "userprog/process.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"

#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

#include "threads/malloc.h"

/* File descriptor entry used in each thread's file descriptor table. */
struct file_descriptor
  {
    int fd;                     /* File descriptor number. */
    struct file *file;          /* Underlying file object. */
    struct list_elem elem;      /* List element for thread's fd_list. */
  };

/* Global lock to protect file system operations. */
static struct lock filesys_lock;

/* Helper functions for the per-thread file descriptor table. */
static struct file *fd_to_file (int fd);
static bool fd_close (int fd);

static void validate_user_ptr (const void *uaddr);
static void validate_user_buffer (const void *buffer, unsigned size);
static void validate_user_string (const char *str);
static void syscall_handler (struct intr_frame *);
void sys_exit (int status);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}


// if uaddr is not a valid user address, end the process with exit(-1)
static void
validate_user_ptr (const void *uaddr)
{
  struct thread *t = thread_current ();

  if (uaddr == NULL
      || !is_user_vaddr (uaddr)
      || pagedir_get_page (t->pagedir, uaddr) == NULL)
    {
      sys_exit (-1);
    }
}

/* Validates that the buffer [buffer, buffer + size) lies in user space and
   is mapped in the current process's page table. This is a simple per-byte
   check, which is slow but sufficient for the project. */
static void
validate_user_buffer (const void *buffer, unsigned size)
{
  const uint8_t *buf = buffer;
  unsigned i;

  for (i = 0; i < size; i++)
    {
      validate_user_ptr (buf + i);
    }
}

/* Validates that a user string is readable up to and including its
   terminating '\0'. This is a simplistic implementation that checks
   each byte until it sees '\0'. */
static void
validate_user_string (const char *str)
{
  validate_user_ptr (str);
  while (*str != '\0')
    {
      str++;
      validate_user_ptr (str);
    }
}




// static void
// syscall_handler (struct intr_frame *f UNUSED) 
// {
//   printf ("system call!\n");
//   thread_exit ();
// }

static void
syscall_handler (struct intr_frame *f) 
{
  void *esp = f->esp;

  /* Validate the 4-byte system call number on the user stack. */
  validate_user_buffer (esp, sizeof (int));

  /* System call number is the first word on the stack. */
  int syscall_no = *(int *) esp;

  switch (syscall_no)
    {
    case SYS_HALT:
      shutdown_power_off ();
      break;

    case SYS_EXIT:
      {
        /* void exit (int status); */
        void *arg1 = (uint8_t *) esp + 4;   /* status */
        validate_user_buffer (arg1, sizeof (int));

        int status = *(int *) arg1;
        sys_exit (status);
        break;
      }

    case SYS_EXEC:
      {
        /* pid_t exec (const char *cmd_line); */
        void *arg1 = (uint8_t *) esp + 4;   /* cmd_line pointer on user stack */

        /* Validate pointer-size argument on user stack. */
        validate_user_buffer (arg1, sizeof (const char *));

        const char *cmd_line = *(const char **) arg1;
        if (cmd_line == NULL)
          sys_exit (-1);

        /* Validate the entire user string. */
        validate_user_string (cmd_line);

        tid_t tid = process_execute (cmd_line);
        f->eax = (tid == TID_ERROR) ? -1 : tid;
        break;
      }

    case SYS_WAIT:
      {
        /* int wait (pid_t pid); */
        void *arg1 = (uint8_t *) esp + 4;   /* pid (tid_t) */

        validate_user_buffer (arg1, sizeof (tid_t));
        tid_t child_tid = *(tid_t *) arg1;

        int status = process_wait (child_tid);
        f->eax = status;
        break;
      }

    case SYS_WRITE:
      {
        /* ssize_t write (int fd, const void *buffer, unsigned size); */

        void *arg1 = (uint8_t *) esp + 4;   /* fd */
        void *arg2 = (uint8_t *) esp + 8;   /* buffer */
        void *arg3 = (uint8_t *) esp + 12;  /* size */

        validate_user_buffer (arg1, sizeof (int));
        validate_user_buffer (arg2, sizeof (const void *));
        validate_user_buffer (arg3, sizeof (unsigned));

        int fd = *(int *) arg1;
        const void *buffer = *(const void **) arg2;
        unsigned size = *(unsigned *) arg3;

        if (size > 0)
          validate_user_buffer (buffer, size);

        int bytes_written = 0;

        if (fd == 1)
          {
            /* Standard output: write to console. */
            putbuf (buffer, size);
            bytes_written = (int) size;
          }
        else if (fd > 1)
          {
            /* Write to an open file. */
            struct file *file = fd_to_file (fd);
            if (file == NULL)
              {
                bytes_written = -1;
              }
            else
              {
                lock_acquire (&filesys_lock);
                bytes_written = file_write (file, buffer, size);
                lock_release (&filesys_lock);
              }
          }
        else
          {
            /* fd == 0 (stdin) or negative: invalid for write(). */
            bytes_written = -1;
          }

        f->eax = bytes_written;
        break;
      }

    case SYS_READ:
      {
        /* int read (int fd, void *buffer, unsigned size); */

        void *arg1 = (uint8_t *) esp + 4;   /* fd */
        void *arg2 = (uint8_t *) esp + 8;   /* buffer */
        void *arg3 = (uint8_t *) esp + 12;  /* size */

        validate_user_buffer (arg1, sizeof (int));
        validate_user_buffer (arg2, sizeof (void *));
        validate_user_buffer (arg3, sizeof (unsigned));

        int fd = *(int *) arg1;
        void *buffer = *(void **) arg2;
        unsigned size = *(unsigned *) arg3;

        if (size > 0)
          validate_user_buffer (buffer, size);

        int bytes_read = 0;

        if (fd == 0)
          {
            /* Read from standard input (keyboard). */
            unsigned i;
            uint8_t *buf = buffer;
            for (i = 0; i < size; i++)
              {
                buf[i] = input_getc ();
              }
            bytes_read = (int) size;
          }
        else if (fd > 1)
          {
            struct file *file = fd_to_file (fd);
            if (file == NULL)
              {
                bytes_read = -1;
              }
            else
              {
                lock_acquire (&filesys_lock);
                bytes_read = file_read (file, buffer, size);
                lock_release (&filesys_lock);
              }
          }
        else
          {
            /* fd == 1 (stdout) or invalid: cannot read. */
            bytes_read = -1;
          }

        f->eax = bytes_read;
        break;
      }

    case SYS_CREATE:
      {
        /* bool create (const char *file, unsigned initial_size); */

        void *arg1 = (uint8_t *) esp + 4;   /* file */
        void *arg2 = (uint8_t *) esp + 8;   /* initial_size */

        validate_user_buffer (arg1, sizeof (const char *));
        validate_user_buffer (arg2, sizeof (unsigned));

        const char *file = *(const char **) arg1;
        unsigned initial_size = *(unsigned *) arg2;

        if (file == NULL)
          sys_exit (-1);

        validate_user_string (file);

        bool success;
        lock_acquire (&filesys_lock);
        success = filesys_create (file, initial_size);
        lock_release (&filesys_lock);

        f->eax = success;
        break;
      }

    case SYS_REMOVE:
      {
        /* bool remove (const char *file); */

        void *arg1 = (uint8_t *) esp + 4;   /* file */

        validate_user_buffer (arg1, sizeof (const char *));
        const char *file = *(const char **) arg1;

        if (file == NULL)
          sys_exit (-1);

        validate_user_string (file);

        bool success;
        lock_acquire (&filesys_lock);
        success = filesys_remove (file);
        lock_release (&filesys_lock);

        f->eax = success;
        break;
      }

    case SYS_OPEN:
      {
        /* int open (const char *file); */

        void *arg1 = (uint8_t *) esp + 4;   /* file */

        validate_user_buffer (arg1, sizeof (const char *));
        const char *file_name = *(const char **) arg1;

        if (file_name == NULL)
          sys_exit (-1);

        validate_user_string (file_name);

        struct file *file;
        int fd = -1;

        lock_acquire (&filesys_lock);
        file = filesys_open (file_name);
        lock_release (&filesys_lock);

        if (file == NULL)
          {
            f->eax = -1;
            break;
          }

        struct file_descriptor *fde = malloc (sizeof *fde);
        if (fde == NULL)
          {
            file_close (file);
            f->eax = -1;
            break;
          }

        struct thread *cur = thread_current ();
        fde->fd = cur->next_fd++;
        fde->file = file;
        list_push_back (&cur->fd_list, &fde->elem);

        fd = fde->fd;
        f->eax = fd;
        break;
      }

    case SYS_FILESIZE:
      {
        /* int filesize (int fd); */

        void *arg1 = (uint8_t *) esp + 4;   /* fd */

        validate_user_buffer (arg1, sizeof (int));
        int fd = *(int *) arg1;

        struct file *file = fd_to_file (fd);
        if (file == NULL)
          {
            f->eax = -1;
          }
        else
          {
            lock_acquire (&filesys_lock);
            int length = file_length (file);
            lock_release (&filesys_lock);
            f->eax = length;
          }
        break;
      }

    case SYS_SEEK:
      {
        /* void seek (int fd, unsigned position); */

        void *arg1 = (uint8_t *) esp + 4;   /* fd */
        void *arg2 = (uint8_t *) esp + 8;   /* position */

        validate_user_buffer (arg1, sizeof (int));
        validate_user_buffer (arg2, sizeof (unsigned));

        int fd = *(int *) arg1;
        unsigned position = *(unsigned *) arg2;

        struct file *file = fd_to_file (fd);
        if (file != NULL)
          {
            lock_acquire (&filesys_lock);
            file_seek (file, position);
            lock_release (&filesys_lock);
          }
        /* No return value. */
        break;
      }

    case SYS_TELL:
      {
        /* unsigned tell (int fd); */

        void *arg1 = (uint8_t *) esp + 4;   /* fd */

        validate_user_buffer (arg1, sizeof (int));
        int fd = *(int *) arg1;

        struct file *file = fd_to_file (fd);
        if (file == NULL)
          {
            f->eax = -1;
          }
        else
          {
            lock_acquire (&filesys_lock);
            unsigned pos = file_tell (file);
            lock_release (&filesys_lock);
            f->eax = pos;
          }
        break;
      }

    case SYS_CLOSE:
      {
        /* void close (int fd); */

        void *arg1 = (uint8_t *) esp + 4;   /* fd */

        validate_user_buffer (arg1, sizeof (int));
        int fd = *(int *) arg1;

        if (fd >= 2)
          {
            lock_acquire (&filesys_lock);
            fd_close (fd);
            lock_release (&filesys_lock);
          }
        break;
      }

    default:
      /* Unknown system call: terminate the process. */
      sys_exit (-1);
      break;
    }
}



/* Looks up the file associated with a given file descriptor in the
   current thread's file descriptor table.
   Returns NULL if not found. */
static struct file *
fd_to_file (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->fd_list);
       e != list_end (&cur->fd_list);
       e = list_next (e))
    {
      struct file_descriptor *fde = list_entry (e, struct file_descriptor, elem);
      if (fde->fd == fd)
        return fde->file;
    }
  return NULL;
}

/* Closes a file descriptor in the current thread's file descriptor table.
   Returns true if fd was found and closed, false otherwise. */
static bool
fd_close (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->fd_list);
       e != list_end (&cur->fd_list);
       e = list_next (e))
    {
      struct file_descriptor *fde = list_entry (e, struct file_descriptor, elem);
      if (fde->fd == fd)
        {
          file_close (fde->file);
          list_remove (&fde->elem);
          free (fde);
          return true;
        }
    }
  return false;
}



void
sys_exit (int status)
{
  struct thread *cur = thread_current ();

  /* Save exit status in the thread struct (for debugging or future use). */
  cur->exit_status = status;

  /* If this thread has a child_process entry in its parent, update it. */
  if (cur->cp != NULL)
    {
      cur->cp->exit_status = status;
      cur->cp->exited = true;

      /* Wake up the parent waiting in process_wait(). */
      sema_up (&cur->cp->wait_sema);
    }

  /* Print the standard exit message. */
  printf ("%s: exit(%d)\n", thread_name (), status);

    /* Close all open file descriptors belonging to this thread. */
  struct list_elem *e = list_begin (&cur->fd_list);
  while (e != list_end (&cur->fd_list))
    {
      struct file_descriptor *fde = list_entry (e, struct file_descriptor, elem);
      e = list_next (e);

      file_close (fde->file);
      list_remove (&fde->elem);
      free (fde);
    }

  thread_exit ();
}
