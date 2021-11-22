
#include "vm/page.h"

struct list lru_list;
/* lock for lru_list*/
struct lock lru_list_lock;
struct page *lru_clock;

/* if a's vm_entry adress is less than b's vm_entry address return true */
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	struct vm_entry *vme_a = hash_entry(a, struct vm_entry, elem);
	struct vm_entry *vme_b = hash_entry(b, struct vm_entry, elem);

	if(vme_a->vaddr < vme_b->vaddr)
		return true;
	else 
		return false;
}

/* define hash function */
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	return hash_int((int)vme->vaddr);
}

static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	void *physical_address;
	/* if virtual address is loaded on physical memory */
	if(vme->is_loaded == true)
	{
		/*get physical_address and free page */
		physical_address = pagedir_get_page(thread_current()->pagedir, vme->vaddr);
		free_page(physical_address);
		/* clear page table */
		pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
	}
	/* free vm_entry */
	free(vme);
}

void vm_init(struct hash *vm)
{
	hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

void vm_destroy(struct hash *vm)
{
	hash_destroy(vm, vm_destroy_func);
}
/* find vm_entry using virtual address */
struct vm_entry *find_vme(void *vaddr)
{
	struct vm_entry vme;
	struct hash_elem *element;
	/* try to find vm_entry by hash_find*/
	vme.vaddr = pg_round_down(vaddr);
	element = hash_find(&thread_current()->vm, &vme.elem);
	/* if get a element return vm_entry */
	if(element != NULL)
	{
		return hash_entry(element, struct vm_entry, elem);
	}
	return NULL;
}

bool insert_vme(struct hash *vm, struct vm_entry *vme)
{
	bool result = false;
	/* if hash_insert is success, return true */
	if(hash_insert(vm, &vme->elem) == NULL)
		result = true;
	return result;
}

bool delete_vme(struct hash *vm, struct vm_entry *vme)
{
	bool result = false;
	/* if hash_delete is success, return true */
	if(hash_delete(vm, &vme->elem) != NULL)
		result = true;
	free(vme);
	return result;   
}

bool load_file(void *kaddr, struct vm_entry *vme)
{
	bool result = false;   
	/* file read and if success, return true */
	/* read vm_entry's file to physical memory.*/
	if((int)vme->read_bytes == file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset))
	{
		result = true;
		memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
	} 
	return result;
}

int file_mmap(int fd, void *addr)
{
	struct thread *cur = thread_current();
	struct mmap_file *mmap_file_entry;
	struct vm_entry *vme;
	struct file *mmap_file;
	uint32_t file_len;
	int32_t offset = 0;
	void *virtual_address = addr;
	size_t page_read_bytes;
	size_t page_zero_bytes;

	/* check addr is valid */
	if((uint32_t)addr%PGSIZE != 0 || addr == NULL)
	{
		return -1;
	}
	mmap_file_entry = malloc(sizeof(struct mmap_file));
	if(mmap_file_entry == NULL)
		return -1;
	/* reopen the file. if fail to reopen, return false */
	lock_acquire(&file_lock);
	mmap_file = file_reopen(get_file(fd));
	if(mmap_file == NULL)
	{
		lock_release(&file_lock);
		printf("File reopen fail!\n");
		return -1;
	}
	/* init mapid and increase thread_current's mapid */
	cur->mapid += 1;
	mmap_file_entry->mapid = cur->mapid;

	/* initialize mmap_file's vme_list */
	list_init(&(mmap_file_entry->vme_list));

	mmap_file_entry->file = mmap_file;
	file_len = file_length(mmap_file);
	lock_release(&file_lock);

	while(file_len > 0)
	{
		vme = malloc(sizeof(struct vm_entry));
		if(vme == NULL)
			return -1;
		/* calculate how to fill vm_entry 
		   we will read page_read_bytes from file
		   and zero the final page_zero_bytes bytes.*/
		page_read_bytes = file_len < PGSIZE ? file_len : PGSIZE;
		page_zero_bytes = PGSIZE - page_read_bytes;
		/* initialize vm_entry */
		vme->type      = VM_FILE;
		vme->vaddr     = virtual_address;
		vme->writable  = true;
		vme->is_loaded = false;
		vme->pinned    = false;
		vme->file      = mmap_file;
		vme->offset    = offset;
		vme->read_bytes= page_read_bytes;
		vme->zero_bytes= page_zero_bytes;
		/* insert vm_entry to hash. if fail, return false */
		if(insert_vme(&cur->vm, vme) == false)
		{
			return -1;
		}
		/* insert vm_entry to mmap_file */
		list_push_back(&(mmap_file_entry->vme_list), &(vme->mmap_elem));
		/* advance */
		file_len -= page_read_bytes;
		offset += page_read_bytes;
		virtual_address += PGSIZE;
	}
	/* insert mmap_file to thread_current()'s mmap_list */
	list_push_back(&cur->mmap_list,&mmap_file_entry->elem);
	return cur->mapid;
}

void file_munmap(int mapping)
{
	struct mmap_file *map_file;
	struct thread *cur = thread_current();
	struct list_elem *element;
	struct list_elem *tmp;
	/* find mmap_file which mapid is equal to mapping */
	for(element = list_begin(&cur->mmap_list) ; element != list_end(&cur->mmap_list) ; element = list_next(element))
	{
		map_file = list_entry(element, struct mmap_file, elem);
		/* if mapping is CLOSE_ALL, close all map_file.
		   find mmap_file's mapid is equal to mapping and remove mmap_file from mmap_list. */
		if(mapping == CLOSE_ALL || map_file->mapid == mapping)
		{
			do_munmap(map_file);
			/* close file */

			file_close(map_file->file);
			/* remove from mmap_list */
			tmp = list_prev(element);
			list_remove(element);
			element = tmp;
			/* free the mmap_file */
			free(map_file);
			if(mapping != CLOSE_ALL)
				break;
		}
	}
}

void do_munmap(struct mmap_file *mmap_file)
{
	lock_acquire(&file_lock);
	struct thread *cur = thread_current();
	struct list_elem *element;
	struct list_elem *tmp;
	struct list *vm_list = &(mmap_file->vme_list);
	struct vm_entry *vme;
	void *physical_address;
	/* remove all vm_entry */
	for(element = list_begin(vm_list); element != list_end(vm_list); element = list_next(element))
	{
		vme = list_entry(element, struct vm_entry, mmap_elem);
		/* if vm_entry is loaded to physical memory */
		if(vme->is_loaded == true)
		{
			physical_address = pagedir_get_page(cur->pagedir, vme->vaddr);
			/* if vm_entry's physical memory is dirty, write to disk */
			if(pagedir_is_dirty(cur->pagedir, vme->vaddr) == true)
			{
				file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->offset);
			}
			/* clear page table */
			pagedir_clear_page(cur->pagedir, vme->vaddr);
			/* free physical memory */
			free_page(physical_address);
		}
		/* remove from vme_list*/
		tmp = list_prev(element);
		list_remove(element);
		element = tmp;
		/* delete vm_entry from hash and free */
		delete_vme(&cur->vm, vme);
	}
	lock_release(&file_lock);
}

void lru_list_init(void)
{
	/* initialize */
	list_init(&lru_list);
	lock_init(&lru_list_lock);
	lru_clock = NULL;
}

/* add page to lru list */
void add_page_to_lru_list(struct page *page)
{
	if(page != NULL)
	{
     	lock_acquire(&lru_list_lock);
		list_push_back(&lru_list, &page->lru);
		lock_release(&lru_list_lock);
	}
}

/* delete page from lru list */
void del_page_from_lru_list(struct page* page)
{
	if(page != NULL)
	{
		if(lru_clock == page)
		{
			lru_clock = list_entry(list_remove(&page->lru), struct page, lru);
		}
		else
			list_remove(&page->lru);
	}
}

struct page *alloc_page(enum palloc_flags flags)
{
	struct page *new_page;
	void *kaddr;
	if((flags & PAL_USER) == 0)
		return NULL;
	/* allocate physical memory */
	kaddr = palloc_get_page(flags);
	/* if fail, free physical memory and retry physical memory allocate*/
	while(kaddr == NULL)
	{
		try_to_free_pages();
		kaddr = palloc_get_page(flags);
	}
	new_page = malloc(sizeof(struct page));
	if(new_page == NULL)
	{
		palloc_free_page(kaddr);
		return NULL;
	}
	/* initialize page */
	new_page->kaddr  = kaddr;
	new_page->pg_thread = thread_current();
	/* insert page to lru list */
	add_page_to_lru_list(new_page);
	return new_page;
}

void free_page(void *kaddr)
{
	struct list_elem *element;
	struct page *lru_page;
	lock_acquire(&lru_list_lock);
	/* find page */
	for(element = list_begin(&lru_list); element != list_end(&lru_list); element = list_next(element))
	{
		lru_page = list_entry(element, struct page, lru);
		/* if find page, call the __free_page */
		if(lru_page->kaddr == kaddr)
		{
			__free_page(lru_page);
			break;
		}
	}
	lock_release(&lru_list_lock);
}

void __free_page(struct page *page)
{
	/* free physical memory */
	palloc_free_page(page->kaddr);
	/* delete page from lru_list */
	del_page_from_lru_list(page);
	free(page);
}

struct list_elem* get_next_lru_clock(void)
{
	struct list_elem *element;
	/* if lru_clock is NULL */
	if(lru_clock == NULL)
	{
		element = list_begin(&lru_list);
		/* if lru_list is not empty list, return the first of list */
		if(element != list_end(&lru_list))
		{
			lru_clock = list_entry(element, struct page, lru);
			return element;
		}
		else
		{
			return NULL;
		}
	}
	element = list_next(&lru_clock->lru);
	/* if lru_clock page is final page of lru_list */
	if(element == list_end(&lru_list))
	{
		/* if lru_list has only one page */
		if(&lru_clock->lru == list_begin(&lru_list))
		{
			return NULL;
		}
		else
		{
			/* lru_list has more than one page, lru_clock points list begin page */
			element = list_begin(&lru_list);
		}
	}
	lru_clock = list_entry(element, struct page, lru);
	return element;
}

void try_to_free_pages(void)
{
	struct thread *page_thread;
	struct list_elem *element;
	struct page *lru_page;
	lock_acquire(&lru_list_lock);
	if(list_empty(&lru_list) == true)
	{
		lock_release(&lru_list_lock);
		return;
	}
	while(true)
	{
		/* get next element */
		element = get_next_lru_clock();
		if(element == NULL){
			lock_release(&lru_list_lock);
			return;
		}
		lru_page = list_entry(element, struct page, lru);
		if(lru_page->vme->pinned == true)
			continue;
		page_thread = lru_page->pg_thread;
		/* if page address is accessed, set accessed bit 0 and continue(it's not victim) */
		if(pagedir_is_accessed(page_thread->pagedir, lru_page->vme->vaddr))
		{
			pagedir_set_accessed(page_thread->pagedir, lru_page->vme->vaddr, false);
			continue;
		}
		/* if not accessed, it's victim */
		/* if page is dirty */
		if(pagedir_is_dirty(page_thread->pagedir, lru_page->vme->vaddr) || lru_page->vme->type == VM_ANON)
		{
			/* if vm_entry is mmap file, don't call swap out.*/
			if(lru_page->vme->type == VM_FILE)
			{
				lock_acquire(&file_lock);
				file_write_at(lru_page->vme->file, lru_page->kaddr ,lru_page->vme->read_bytes, lru_page->vme->offset);
				lock_release(&file_lock);
			}
			/* if not mmap_file, change type to ANON and call swap_out function */
			else
			{
				lru_page->vme->type = VM_ANON;
				lru_page->vme->swap_slot = swap_out(lru_page->kaddr);
 			}
		}
		lru_page->vme->is_loaded = false;
		pagedir_clear_page(page_thread->pagedir, lru_page->vme->vaddr);
		__free_page(lru_page);
		break;
	}
    lock_release(&lru_list_lock);
	return;
}