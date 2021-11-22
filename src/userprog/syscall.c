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

  check_useradd(f->esp, f->esp);
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
    check_useradd(f->esp + 4, f->esp);
    exit(*((int *)(f->esp + 4)));
    break;
  case SYS_EXEC:
    check_useradd(f->esp + 4, f->esp);
    f->eax = sys_exec(*(const char**)(f->esp + 4));
    break;
  case SYS_WAIT:
    check_useradd(f->esp + 4, f->esp);
    f->eax = sys_wait(*(int*)(f->esp + 4));
    break;
  case SYS_CREATE:
    check_useradd(f->esp + 4, f->esp);
    check_useradd(f->esp + 8, f->esp);
    check_valid_string(*((void **)(f->esp + 4)), f->esp);
    f->eax = create((*(char **)(f->esp + 4)), *((unsigned int *)(f->esp + 8)));
    break;
  case SYS_REMOVE:    
    check_useradd(f->esp + 4, f->esp);
    check_valid_string(*((void **)(f->esp + 4)), f->esp);
    f->eax = remove(*(char **)(f->esp + 4));
    break;    
  case SYS_OPEN:
    check_useradd(f->esp + 4, f->esp);
    check_valid_string(*((void **)(f->esp + 4)), f->esp);
    f->eax = open(*(const char**)(f->esp + 4));
    break;    
  case SYS_FILESIZE:
    check_useradd(f->esp + 4, f->esp);
    f->eax = filesize(*(int *)(f->esp + 4));
    break;    
  case SYS_READ:
    check_useradd(f->esp + 4, f->esp);
    check_useradd(f->esp + 8, f->esp);
    check_useradd(f->esp + 12, f->esp);
    check_valid_buffer(*(void **)(f->esp + 8), *(unsigned *)(f->esp + 12), true, f->esp);
    f->eax = read(*(int*)(f->esp + 4), *(char **)(f->esp + 8), *(unsigned *)(f->esp + 12));
    break;
  case SYS_WRITE:
    check_useradd(f->esp + 4, f->esp);
    check_useradd(f->esp + 8, f->esp);
    check_useradd(f->esp + 12, f->esp);
    check_valid_buffer(*(void **)(f->esp + 8), *(unsigned *)(f->esp + 12), false, f->esp);
    f->eax = write(*(int*)(f->esp + 4), *(char **)(f->esp + 8), *(unsigned *)(f->esp + 12));
    break;
  case SYS_SEEK:
    check_useradd(f->esp + 4, f->esp);
    check_useradd(f->esp + 8, f->esp);
    seek(*(int*)(f->esp + 4), *(unsigned *)(f->esp + 8));
    break;
  case SYS_TELL:
    check_useradd(f->esp + 4, f->esp);
    f->eax = tell(*(int*)(f->esp + 4));
    break;    
  case SYS_CLOSE:
    check_useradd(f->esp + 4, f->esp);
    close(*(int*)(f->esp + 4));
    break;
  case SYS_MMAP:
    check_useradd(f->esp + 4, f->esp);
    check_useradd(f->esp + 8, f->esp);
    f->eax = sys_mmap(*(int*)(f->esp+4), *(void **)(f->esp + 8));
    break;
  case SYS_MUNMAP:
    check_useradd(f->esp + 4, f->esp);
    munmap(*(int*)(f->esp+4));
    break;
  default:
    break;
  }

  // thread_exit ();
}


void check_valid_string(void* str, void *esp)
{
	char *check_str = (char *)str;
	check_useradd((void *)check_str, esp);
	/* check the all string's address */
	while(*check_str != 0)
	{
		check_str += 1;
		check_useradd(check_str, esp);
	}
}

void check_valid_buffer(void* buffer, unsigned size, bool to_write, void* esp)
{
  int i;
  char* check_buffer = (char*)buffer;
  for(i = 0; i < size; i++)
  {
    struct vm_entry* check = check_useradd(check_buffer, esp);
      if(check != NULL)
      {
        if(check->writable == false && to_write == true)
          exit(-1); 
      }
      check_buffer++;
  }
}

struct vm_entry* check_useradd(void *addr, void *esp)
{
  // if(!is_user_vaddr(addr) || addr < (void *)0x08048000)
  //   exit(-1);
  // struct vm_entry* vme = find_vme(addr);
  // if(vme == NULL)
  // {
  //   if(addr >= 32)
  //   {
  //     if(expand_stack(addr) == false)
  //       exit(-1);
  //   }
  //   else
  //     exit(-1);
  // }
  // return vme;
  struct vm_entry *vme;
	uint32_t address=(unsigned int)addr;
	uint32_t lowest_address=0x8048000;
	uint32_t highest_address=0xc0000000;
	/* if address is user_address */
	if(address >= lowest_address && address < highest_address)
	{
		/* find vm_entry if can't find vm_entry, exit the process */
		vme = find_vme(addr);
		/* if can't find vm_entry */
		if(vme == NULL)
		{
			if(addr >= (esp - 32)){
				if(expand_stack(addr) == false)
					exit(-1);
			}
			else
				exit(-1);
		}
	}
	else
	{
		exit(-1);
	}

  return vme;
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
  // check_useradd(file);
  int result;
  lock_acquire(&file_lock);
  result = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return result;
}

int remove(const char *file)
{
  if(file == NULL)
    exit(-1);
  // check_useradd(file);
  int result;
  lock_acquire(&file_lock);
  result = filesys_remove(file);
  lock_release(&file_lock);
  return result;
}

tid_t sys_exec (const char *cmd_line)
{
  tid_t child_tid;
  // check_useradd(cmd_line);
  child_tid = process_execute(cmd_line);

  if (child_tid == -1)
    return -1;

  struct thread * child_thread = get_child_process (child_tid);
  // sema_down(&thread_current()->parent_thread->sema_load);
  if(!child_thread || !child_thread->load_success) 
    return -1;

  return child_tid;

  // if (child_thread->exit_status == 0)
  //   return child_tid;
  // return -1;
}

int sys_wait (tid_t tid)
{
  return process_wait(tid);
}

int open (const char *file)
{
  if(file == NULL)
    return -1;
  // check_useradd(file);
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
  lock_acquire(&file_lock);
  int result = file_length(curr->file_descriptor[fd]);
  lock_release(&file_lock);
  return result;
}

int read (int fd, void *buffer, unsigned size)
{
  // check_useradd(buffer);
  struct thread *curr = thread_current();
  int ret_val;
  if (curr->file_num < fd || fd == 1 || fd < 0)
  {  
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
    return i;
  }
  else
  {
    if(curr->file_descriptor[fd] == NULL)
    {
      return -1;
    }
    if(filesize(fd) < size)
    {
      ret_val = -1;
    }
    lock_acquire(&file_lock);
    ret_val = file_read(curr->file_descriptor[fd], buffer, size);
    lock_release(&file_lock);
  }

  return ret_val;
}

int write(int fd, void *buffer, unsigned size)
{
  // check_useradd(buffer);
  struct thread *curr = thread_current();
  if (curr->file_num < fd || fd == 0 || fd < 0)
    return -1;

  int result = -1;
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
      //exit(-1);
      return -1;
    }
    lock_acquire(&file_lock);
    result = file_write(curr->file_descriptor[fd], buffer, size);
    lock_release(&file_lock);
  }

  // lock_release(&file_lock);
  return result;
}

void seek(int fd, unsigned position)
{
  struct thread* curr = thread_current();
  if (curr->file_num < fd || fd < 0 || curr->file_descriptor[fd] == NULL)
    exit(-1);
  struct file *curr_file = thread_current()->file_descriptor[fd];

  lock_acquire(&file_lock);
  file_seek(curr_file, position);
  lock_release(&file_lock);
}

unsigned tell (int fd)
{
  struct thread* curr = thread_current();
  if (curr->file_num < fd || fd < 0 || curr->file_descriptor[fd] == NULL)
    exit(-1);
  struct file *curr_file = thread_current()->file_descriptor[fd];

  lock_acquire(&file_lock);
  unsigned result =  file_tell(curr_file);
  lock_release(&file_lock);

  return result;
}

void close(int fd)
{
  lock_acquire(&file_lock);
  close_file(fd);
  lock_release(&file_lock);
}

int sys_mmap(int fd, void *addr)
{
	return file_mmap(fd,(void *)addr);
}

void munmap(int mapping)
{
	file_munmap(mapping);
}