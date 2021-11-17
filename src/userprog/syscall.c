#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include <filesys/filesys.h>
#include <devices/shutdown.h>
#include "threads/synch.h"


static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  // printf("in the syscall handler : %d\n", *(int *)(f->esp));
  // printf ("system call! \n");

  check_useradd(f->esp);
  unsigned int handling_num = *((unsigned int *)(f->esp));
  // unit32_t* arg = (unit32_t *)malloc(sizeof(unit32_t) * num_arg);

  // check_useradd(f->esp);
  // check_useradd(f->esp + (num_arg - 1) * 4);

  // copy_argument(f->esp, arg, num_arg);

  switch (handling_num)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    check_useradd(f->esp + 4);
    exit(*((int *)(f->esp + 4)));
    break;
  case SYS_EXEC:
    check_useradd(f->esp + 4);
    f->eax = exec(*(const char**)(f->esp + 4));
    break;
  case SYS_WAIT:
    check_useradd(f->esp + 4);
    f->eax = wait(*(int*)(f->esp + 4));
    break;
  case SYS_CREATE:
    check_useradd(f->esp + 4);
    check_useradd(f->esp + 8);
    f->eax = create((*(char **)(f->esp + 4)), *((unsigned int *)(f->esp + 8)));
    break;
  case SYS_REMOVE:    
    check_useradd(f->esp + 4);
    f->eax = remove(*(char **)(f->esp + 4));
    break;    
  case SYS_OPEN:
    check_useradd(f->esp + 4);
    f->eax = open(*(const char**)(f->esp + 4));
    break;    
  case SYS_FILESIZE:
    check_useradd(f->esp + 4);
    f->eax = filesize(*(int *)(f->esp + 4));
    break;    
  case SYS_READ:
    check_useradd(f->esp + 4);
    check_useradd(f->esp + 8);
    check_useradd(f->esp + 12);
    f->eax = read(*(int*)(f->esp + 4), *(char **)(f->esp + 8), *(unsigned *)(f->esp + 12));
    break;
  case SYS_WRITE:
    check_useradd(f->esp + 4);
    check_useradd(f->esp + 8);
    check_useradd(f->esp + 12);
    f->eax = write(*(int*)(f->esp + 4), *(char **)(f->esp + 8), *(unsigned *)(f->esp + 12));
    break;
  case SYS_SEEK:
    check_useradd(f->esp + 4);
    check_useradd(f->esp + 8);
    seek(*(int*)(f->esp + 4), *(unsigned *)(f->esp + 8));
    break;
  case SYS_TELL:
    check_useradd(f->esp + 4);
    f->eax = tell(*(int*)(f->esp + 4));
    break;    
  case SYS_CLOSE:
    check_useradd(f->esp + 4);
    close(*(int*)(f->esp + 4));
    break;    
  default:
    break;
  }

  // thread_exit ();
}

void check_useradd(void *addr)
{
  if(!is_user_vaddr(addr))
    exit(-1);
 
  return;
}

struct thread *get_child_process (int pid)
{
  struct list_elem* e;
  struct thread* cur = thread_current();
  for(e = list_begin(&(cur->child_list)); e != list_end(&cur->child_list); e = list_next(e))
  {
    struct thread* check_thread = list_entry(e, struct thread, child_elem);
    if (pid == check_thread->tid)
      return check_thread;
  }

  return NULL;
}

void remove_child_process(struct thread *cp)
{
  list_remove (&(cp->child_elem));
}


void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread *t = thread_current();

  t->exit_status = status;

  printf("%s: exit(%d)\n", t->name, status);  

  thread_exit();
}

int create(const char* file, unsigned int initial_size)
{
  if(file == NULL)
    exit(-1);
  check_useradd(file);
  int result;
  result = filesys_create(file, initial_size);
  return result;
}

int remove(const char *file)
{
  if(file == NULL)
    exit(-1);
  check_useradd(file);
  int result;
  result = filesys_remove(file);
  return result;
}

tid_t exec (const char *cmd_line)
{
  tid_t child_tid;
  check_useradd(cmd_line);
  child_tid = process_execute(cmd_line);

  if (child_tid == -1)
    return -1;

  struct thread * child_thread = get_child_process (child_tid);
  // sema_down(&thread_current()->parent_thread->sema_load);

  return child_tid;

  // if (child_thread->exit_status == 0)
  //   return child_tid;
  // return -1;
}

int wait (tid_t tid)
{
  return process_wait(tid);
}

int open (const char *file)
{
  if(file == NULL)
    return -1;
  check_useradd(file);
  lock_acquire(&file_lock);
  struct file* open_file = filesys_open(file);

  if(strcmp(file, thread_current()->name) == 0)
    file_deny_write(open_file);

  if (open_file == NULL)
  {
    lock_release(&file_lock);
    return -1;
  }
  int ret_val = process_add_file(open_file);
  lock_release(&file_lock);
  return ret_val;
}

int filesize (int fd)
{
  struct thread *curr = thread_current();
  if (curr->file_num < fd || fd < 0 || curr->file_descriptor[fd] == NULL)
    exit(-1);
  return file_length(curr->file_descriptor[fd]);
}

int read (int fd, void *buffer, unsigned size)
{
  lock_acquire(&file_lock);
  check_useradd(buffer);
  struct thread *curr = thread_current();
  int ret_val;
  if (curr->file_num < fd || fd == 1 || fd < 0)
  {  
    lock_release(&file_lock);
    return -1;
  }

  if (fd == 0)
  {
    int i;
    for (i = 0; i < size; i++)
    {
      if(input_getc() == NULL)
        break;
    }
    lock_release(&file_lock);
    return i;
  }
  else
  {
    if(curr->file_descriptor[fd] == NULL)
    {
      lock_release(&file_lock);
      return -1;
    }
    if(filesize(fd) < size)
    {
      lock_release(&file_lock);
      return -1;
    }
    ret_val = file_read(curr->file_descriptor[fd], buffer, size);
  }
  lock_release(&file_lock);

  return ret_val;
}

int write(int fd, void *buffer, unsigned size)
{
  check_useradd(buffer);
  struct thread *curr = thread_current();
  if (curr->file_num < fd || fd == 0 || fd < 0)
    return -1;

  lock_acquire(&file_lock);
  int result;
  if (fd == 1)
  {
    putbuf((const char*)buffer, size);
    result = size;
  }
  else
  {
    // if(thread_current()->file_descriptor[fd]->deny_write)

    if(curr->file_descriptor[fd] == NULL)
    {    
      lock_release(&file_lock);
      exit(-1);
    }
    result = file_write(curr->file_descriptor[fd], buffer, size);
  }

  lock_release(&file_lock);
  // lock_release(&file_lock);
  return result;
}

void seek(int fd, unsigned position)
{
  struct thread* curr = thread_current();
  if (curr->file_num < fd || fd < 0 || curr->file_descriptor[fd] == NULL)
    exit(-1);
  struct file *curr_file = thread_current()->file_descriptor[fd];
  file_seek(curr_file, position);
}

unsigned tell (int fd)
{
  struct thread* curr = thread_current();
  if (curr->file_num < fd || fd < 0 || curr->file_descriptor[fd] == NULL)
    exit(-1);
  struct file *curr_file = thread_current()->file_descriptor[fd];
  return file_tell(curr_file);
}

void close(int fd)
{
  close_file(fd);
}