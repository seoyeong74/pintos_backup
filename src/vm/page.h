#ifndef VM_PAGE_HEADER
#define VM_PAGE_HEADER

#include "lib/kernel/hash.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/thread.h"

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2
#define VM_FRAME 3

struct vm_entry{
    uint8_t type; 
    void* vaddr;
    bool writable; 
    bool is_loaded; 
    struct file* file;

    struct list_elem mmap_elem;
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;

    size_t swap_slot; 

    struct hash_elem hash_elem; 
};

void vm_init (struct hash *vm);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
unsigned page_hash (const struct hash_elem *p_, void *aux);

bool insert_vme (struct hash *vm, struct vm_entry *vme);
bool delete_vme (struct hash *vm, struct vm_entry *vme);
 struct vm_entry *find_vme (void *vaddr);
 void vm_destroy ();

#endif