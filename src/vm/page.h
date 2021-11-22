#ifndef PAGE_H
#define PAGE_H

#include <threads/palloc.h>
#include <threads/malloc.h>
#include <hash.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "filesys/file.h"

#define VM_BIN 1 
#define VM_FILE 2
#define VM_ANON 3
#define CLOSE_ALL 9999

/* struct for vm_entry */
struct vm_entry{
	uint8_t type;                      // VM_BIN, VM_FILE, VM_ANON
	void *vaddr;                       // virtual address 
	bool writable;                     
	bool is_loaded;                    // if true, physical memory is loaded
	bool pinned;
	struct file *file;
	struct list_elem mmap_elem;        // list_elem for mmap_file's vm_list
	size_t offset;
	size_t read_bytes;                   
	size_t zero_bytes;
	size_t swap_slot;
	struct hash_elem elem;             // hash elem for thread's vm
};

/* struct for mmap_file*/
struct mmap_file{
	int mapid;
	struct file *file;
	struct list_elem elem;             // list_elem for thread's mmap_list
	struct list vme_list;               // vm_entry list
};

/* struct for page */
struct page{
	void *kaddr;
	struct vm_entry *vme;
	struct thread *pg_thread;
	struct list_elem lru;
};

void vm_init(struct hash *vm);
void vm_destroy(struct hash *vm);
struct vm_entry *find_vme(void *vaddr);
bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);
struct vm_entry *find_vme(void *vaddr);
bool load_file(void *kaddr, struct vm_entry *vme);
int file_mmap(int fd, void *addr);
void file_munmap(int mapping);
void do_munmap(struct mmap_file *mmap_file);

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED);
static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED);

void lru_list_init(void);
void add_page_to_lru_list(struct page *page);
void del_page_from_lru_list(struct page *page);
struct page *alloc_page(enum palloc_flags flag);
void free_page(void *kaddr);
void __free_page(struct page *page);
struct list_elem* get_next_lru_clock(void);
void try_to_free_pages(void);

#endif 