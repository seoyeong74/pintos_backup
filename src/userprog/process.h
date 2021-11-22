#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"
#include "vm/swap.h"

#define MAX_STACK_SIZE (1 << 23)

int process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

int process_add_file(struct file * f);
struct file* get_file(int fd);
void close_file(int fd);

static bool install_page (void *upage, void *kpage, bool writable);
bool handle_mm_fault(struct vm_entry *vme);

bool expand_stack(void *addr);

#endif /* userprog/process.h */