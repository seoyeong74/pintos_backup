#ifndef SWAP_H
#define SWAP_H

#define SECTORS_PER_PAGE 8
#define SWAP_FREE 0
#define SWAP_USED 1

#include "devices/block.h"
#include "threads/synch.h"
#include "lib/kernel/bitmap.h"
#include "vm/page.h"

void swap_init(void);
void swap_in(size_t used_index, void* kaddr);
size_t swap_out(void* kaddr);

#endif