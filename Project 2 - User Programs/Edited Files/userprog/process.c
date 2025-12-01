#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "threads/malloc.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"

#include "userprog/syscall.h"


struct start_process_args
  {
    char *file_name;                 /* Command line / program name copy. */
    struct child_process *cp;        /* Child process entry in parent's list. */
  };


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  struct thread *cur = thread_current ();
  struct child_process *cp;
  struct start_process_args *spa;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a child_process entry for this new child. */
  cp = malloc (sizeof *cp);
  if (cp == NULL)
    {
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }
  cp->tid = TID_ERROR;        /* Temporary until thread_create succeeds. */
  cp->exit_status = -1;
  cp->exited = false;
  cp->waited = false;

  /* Initialize synchronization primitives. */
  sema_init (&cp->wait_sema, 0);
  sema_init (&cp->load_sema, 0);
  cp->load_success = false;

  /* Insert into parent's children list. */
  list_push_back (&cur->children, &cp->elem);

  /* Allocate arguments structure for start_process. */
  spa = malloc (sizeof *spa);
  if (spa == NULL)
    {
      list_remove (&cp->elem);
      free (cp);
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }
  spa->file_name = fn_copy;   /* Full command line for the child. */
  spa->cp = cp;

  /* Extract program name (first token) from file_name for the thread name. */
  char prog_name[16];
  strlcpy (prog_name, file_name, sizeof prog_name);
  char *save_ptr;
  char *thread_name = strtok_r (prog_name, " ", &save_ptr);
  if (thread_name == NULL)
    thread_name = prog_name;

  /* Create a new thread to execute FILE_NAME. 
     Use only the program name (first token) as the thread name. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, spa);
  if (tid == TID_ERROR)
    {
      list_remove (&cp->elem);
      free (cp);
      free (spa);
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }

  /* Now we know the child's tid. */
  cp->tid = tid;

  /* Wait until the child finishes loading the executable. */
  sema_down (&cp->load_sema);

  /* If load failed in the child, return an error. */
  if (!cp->load_success)
    {
      list_remove (&cp->elem);
      free (cp);
      /* fn_copy was freed by the child in start_process. */
      return TID_ERROR;
    }

  return tid;
}





/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  struct start_process_args *args = args_;
  char *file_name = args->file_name;
  struct child_process *cp = args->cp;
  struct intr_frame if_;
  bool success;

  struct thread *cur = thread_current ();
  cur->cp = cp;

  /* We no longer need the args wrapper. */
  free (args);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* Inform the parent about load result. */
  cp->load_success = success;
  sema_up (&cp->load_sema);

  /* We are done with the command line copy. */
  palloc_free_page (file_name);

  if (!success) 
    {
      /* If load failed, terminate with exit status -1. */
      sys_exit (-1);
      /* Not reached, sys_exit() calls thread_exit(). */
    }

  /* Optional: hex_dump for debugging the initial user stack. */
  //hex_dump ((uintptr_t) if_.esp, if_.esp, 128, true);

  /* Start the user process by simulating a return from an interrupt. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}




/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct child_process *cp = NULL;

  /* Find the child_process entry for the given child_tid. */
  for (e = list_begin (&cur->children); e != list_end (&cur->children);
       e = list_next (e))
    {
      struct child_process *c = list_entry (e, struct child_process, elem);
      if (c->tid == child_tid)
        {
          cp = c;
          break;
        }
    }

  /* Not a child of this process. */
  if (cp == NULL)
    return -1;

  /* Already waited on this child. */
  if (cp->waited)
    return -1;

  /* Wait until the child calls exit(). */
  if (!cp->exited)
    sema_down (&cp->wait_sema);

  /* Now the child has exited, retrieve status. */
  cp->waited = true;
  int status = cp->exit_status;

  /* Remove from the list and free the child_process entry. */
  list_remove (&cp->elem);
  free (cp);

  return status;
}


/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* If this process has an executable file, allow writes and close it. */
  if (cur->exec_file != NULL)
    {
      file_allow_write (cur->exec_file);
      file_close (cur->exec_file);
      cur->exec_file = NULL;
    }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}


/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

//static bool setup_stack (void **esp);
static bool setup_stack (void **esp, const char *cmdline);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);




/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
// bool
// load (const char *file_name, void (**eip) (void), void **esp) 
// {
//   struct thread *t = thread_current ();
//   struct Elf32_Ehdr ehdr;
//   struct file *file = NULL;
//   off_t file_ofs;
//   bool success = false;
//   int i;

//   /* Allocate and activate page directory. */
//   t->pagedir = pagedir_create ();
//   if (t->pagedir == NULL) 
//     goto done;
//   process_activate ();

//   /* Open executable file. */
//   file = filesys_open (file_name);
//   if (file == NULL) 
//     {
//       printf ("load: %s: open failed\n", file_name);
//       goto done; 
//     }

//   /* Read and verify executable header. */
//   if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
//       || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
//       || ehdr.e_type != 2
//       || ehdr.e_machine != 3
//       || ehdr.e_version != 1
//       || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
//       || ehdr.e_phnum > 1024) 
//     {
//       printf ("load: %s: error loading executable\n", file_name);
//       goto done; 
//     }

//   /* Read program headers. */
//   file_ofs = ehdr.e_phoff;
//   for (i = 0; i < ehdr.e_phnum; i++) 
//     {
//       struct Elf32_Phdr phdr;

//       if (file_ofs < 0 || file_ofs > file_length (file))
//         goto done;
//       file_seek (file, file_ofs);

//       if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
//         goto done;
//       file_ofs += sizeof phdr;
//       switch (phdr.p_type) 
//         {
//         case PT_NULL:
//         case PT_NOTE:
//         case PT_PHDR:
//         case PT_STACK:
//         default:
//           /* Ignore this segment. */
//           break;
//         case PT_DYNAMIC:
//         case PT_INTERP:
//         case PT_SHLIB:
//           goto done;
//         case PT_LOAD:
//           if (validate_segment (&phdr, file)) 
//             {
//               bool writable = (phdr.p_flags & PF_W) != 0;
//               uint32_t file_page = phdr.p_offset & ~PGMASK;
//               uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
//               uint32_t page_offset = phdr.p_vaddr & PGMASK;
//               uint32_t read_bytes, zero_bytes;
//               if (phdr.p_filesz > 0)
//                 {
//                   /* Normal segment.
//                      Read initial part from disk and zero the rest. */
//                   read_bytes = page_offset + phdr.p_filesz;
//                   zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
//                                 - read_bytes);
//                 }
//               else 
//                 {
//                   /* Entirely zero.
//                      Don't read anything from disk. */
//                   read_bytes = 0;
//                   zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
//                 }
//               if (!load_segment (file, file_page, (void *) mem_page,
//                                  read_bytes, zero_bytes, writable))
//                 goto done;
//             }
//           else
//             goto done;
//           break;
//         }
//     }

//   /* Set up stack. */
//   if (!setup_stack (esp))
//     goto done;

//   /* Start address. */
//   *eip = (void (*) (void)) ehdr.e_entry;

//   success = true;

//  done:
//   /* We arrive here whether the load is successful or not. */
//   file_close (file);
//   return success;
// }

/* load() helpers. */

bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

    /* Copy file_name to extract program name (first token). */
  char *fn_copy = NULL;
  char *save_ptr;
  char *prog_name;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    goto done;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* first token as file name */
  prog_name = strtok_r (fn_copy, " ", &save_ptr);
  if (prog_name == NULL)
    goto done;

  /* Open executable file. */
  file = filesys_open (prog_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", prog_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", prog_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

   done:
  /* We arrive here whether the load is successful or not. */
  if (success)
    {
      /* On success, remember the executable file in the thread and
         deny writes to it while the process is running. */
      t->exec_file = file;
      file_deny_write (file);
      /* Do NOT close 'file' here. It will be closed in process_exit(). */
    }
  else
    {
      /* On failure, close the executable file immediately. */
      if (file != NULL)
        file_close (file);
    }

  if (fn_copy != NULL)
    palloc_free_page (fn_copy);

  return success;

}




static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
// static bool
// setup_stack (void **esp) 
// {
//   uint8_t *kpage;
//   bool success = false;

//   kpage = palloc_get_page (PAL_USER | PAL_ZERO);
//   if (kpage != NULL) 
//     {
//       success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
//       if (success)
//         *esp = PHYS_BASE;
//       else
//         palloc_free_page (kpage);
//     }
//   return success;
// }

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory */
/* Create an initial user stack by mapping a zeroed page at the top of
   user virtual memory, and placing command-line arguments on the stack. */
static bool
setup_stack (void **esp, const char *cmdline) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        {
          *esp = PHYS_BASE;

          /* Make a temporary copy of cmdline for tokenization. */
          char *cmd_copy = palloc_get_page (0);
          if (cmd_copy == NULL)
            return false;
          strlcpy (cmd_copy, cmdline, PGSIZE);

          /* Tokenize cmdline into separate arguments (argv). */
          char *argv[32];
          int argc = 0;
          char *token, *save_ptr;

          for (token = strtok_r (cmd_copy, " ", &save_ptr);
               token != NULL && argc < 32;
               token = strtok_r (NULL, " ", &save_ptr))
            {
              argv[argc++] = token;
            }

          /* Store the addresses of argument strings after pushing them. */
          void *argv_addr[32];

          int i;
          /* Copy argument strings onto the stack in reverse order. */
          for (i = argc - 1; i >= 0; i--)
            {
              size_t len = strlen (argv[i]) + 1; /* Includes '\0'. */
              *esp = (uint8_t *) *esp - len;
              memcpy (*esp, argv[i], len);
              argv_addr[i] = *esp;
            }

          /* Word-align the stack to a 4-byte boundary. */
          uintptr_t esp_uint = (uintptr_t) *esp;
          esp_uint &= 0xfffffffc;
          *esp = (void *) esp_uint;

          /* Now build the argv array on the stack: start with a NULL sentinel. */
          uint32_t *esp32 = (uint32_t *) *esp;

          /* argv[argc] = NULL */
          esp32--;
          *esp32 = 0;

          /* Push addresses of arguments (from last to first). */
          for (i = argc - 1; i >= 0; i--)
            {
              esp32--;
              *esp32 = (uint32_t) argv_addr[i];
            }

          /* esp32 now points to argv[0] on the stack. */
          uint32_t argv_ptr = (uint32_t) esp32;

          /* Push argv itself. */
          esp32--;
          *esp32 = argv_ptr;

          /* Push argc. */
          esp32--;
          *esp32 = (uint32_t) argc;

          /* Push a fake return address. */
          esp32--;
          *esp32 = 0;

          /* Update final stack pointer. */
          *esp = esp32;

          /* Free temporary copy of cmdline. */
          palloc_free_page (cmd_copy);
        }
      else
        palloc_free_page (kpage);
    }
  return success;
}



/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
