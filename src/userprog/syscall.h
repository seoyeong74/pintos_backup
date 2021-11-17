#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "threads/synch.h"

struct lock file_lock;

void syscall_init (void);

void check_useradd(void *addr);
void remove_child_process(struct thread *cp);
struct thread *get_child_process (int pid);

void halt(void);
void exit(int status);
int create(const char* file, unsigned int initial_size);
int remove(const char *file);
tid_t exec (const char *cmd_line);
int wait (tid_t tid);
int open (const char *file);
void close(int fd);
unsigned tell (int fd);
void seek(int fd, unsigned position);
int write(int fd, void *buffer, unsigned size);
int read (int fd, void *buffer, unsigned size);
int filesize (int fd);
#endif /* userprog/syscall.h */