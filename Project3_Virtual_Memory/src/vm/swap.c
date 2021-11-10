#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#include "userprog/syscall.h"
#include "userprog/pagedir.h"

#include "vm/swap.h"

#include "devices/shutdown.h"
#include "devices/block.h"
#include <stdio.h>
#include <string.h>
#include <bitmap.h>
#include <hash.h>
#include <random.h>

//block structure for swap disk
struct block *swap;
//bitmap for swap table
static struct bitmap *swap_bitmap;
//lock for swap
static struct lock swap_lock;
//swap table hash structure
static struct hash swap_table;

/*intializes swap table. It initializes the hash structure that works with 
swap table. Then, we make swap point to swap disk, intializes lock and creates
a bitmap to track swap entries.*/
void 
init_swap_table (void)
{
  if (!hash_init(&swap_table,swap_hash_func,swap_cmp,NULL))
  {
    printf("hash init failed\n");
    shutdown();
  }
  swap = block_get_role(BLOCK_SWAP);
  lock_init(&swap_lock);
  swap_bitmap = bitmap_create(block_size(swap));
  bitmap_set_all(swap_bitmap,0);
}

/*Inserts swap entry. We scan the bitmap to see which sector in swap disk is
empty. Then we copy the data stored in page at adress vaddr to swap disk
Then we store this information in the swap table. Returns the bitmap_location
where the data is stored.*/
size_t
insert_swap_entry (void *vaddr)
{
  size_t swap_idx;
  int i;
  void *sector = malloc(BLOCK_SECTOR_SIZE);
  //8, because one page takes up 8 disk sectors.
  int num_sector = PGSIZE/BLOCK_SECTOR_SIZE;
  
  lock_acquire(&swap_lock);
  swap_idx = bitmap_scan_and_flip (swap_bitmap,0,num_sector,0);
  lock_release(&swap_lock);
  //if swap disk is full, panic kernel
  if (swap_idx == BITMAP_ERROR)
    PANIC("swap disk is full!");
  //printf("%p\n",vaddr);
  //printf("num_sector: %d\n",swap_idx);
  //copy data
  for (i = 0; i < num_sector; i++)
  {
    //printf("hi??\n");
    memcpy(sector,vaddr+i*512,BLOCK_SECTOR_SIZE);
    //printf("sector: %x\n",*(uint32_t *)sector);
    block_write(swap,swap_idx+i,sector);
  }
  //printf("bitmap_loc: %d\n",swap_idx);
  struct st_entry *st_entry = malloc(sizeof(struct st_entry));
  st_entry->vaddr = vaddr;
  st_entry->bitmap_loc = swap_idx;
  hash_insert(&swap_table,&st_entry->hash_elem);
  return st_entry->bitmap_loc;
}

/*removes swap entry so it is retored to frame table. Copy back the data into
the page pointed by new_addr*/
void 
remove_swap_entry (size_t bitmap_loc, void *new_addr)
{
  struct st_entry *st_entry = st_entry_lookup(bitmap_loc);
  if (st_entry == NULL)
    PANIC("no such swap entry\n");
  int num_sector = PGSIZE/BLOCK_SECTOR_SIZE;
  int i = 0;
  
  for (i=0;i<num_sector;i++)
  {
    if (new_addr == NULL)
      break;
    block_read(swap,bitmap_loc+i,new_addr+i*512);
  }
  
  lock_acquire(&swap_lock);
  bitmap_set_multiple (swap_bitmap,bitmap_loc,num_sector,0);
  lock_release(&swap_lock);
  hash_delete(&swap_table,&st_entry->hash_elem);
  free(st_entry);
} 

/*necessray hash function element. Returns hashed value*/
unsigned
swap_hash_func (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct st_entry *p = hash_entry (p_, struct st_entry, hash_elem);
  return hash_bytes (&p->bitmap_loc,sizeof(p->bitmap_loc));
}

/*necessray hash function element. Returns true if b is bigger, false if 
a is bigger.*/
bool
swap_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct st_entry *a = hash_entry (a_, struct st_entry, hash_elem);
  const struct st_entry *b = hash_entry (b_, struct st_entry, hash_elem);
  return a->bitmap_loc < b->bitmap_loc;
}

/*necessray hash function element. Finds hash_entry with key "address"*/
struct st_entry*
st_entry_lookup (size_t bitmap_loc)
{
  struct st_entry f;
  struct hash_elem *e;

  f.bitmap_loc = bitmap_loc;
  e = hash_find(&swap_table,&f.hash_elem);
  return e != NULL ? hash_entry(e,struct st_entry,hash_elem) : NULL;
}


