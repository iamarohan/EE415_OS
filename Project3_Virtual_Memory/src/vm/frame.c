#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

#include "userprog/syscall.h"
#include "userprog/pagedir.h"

#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

#include "devices/shutdown.h"
#include <stdio.h>
#include <string.h>
#include <hash.h>
#include <random.h>


/*initialized frame table (the hash structure that contains frame table)*/
void 
init_frame_table (void)
{
  if (!hash_init(&frame_hash,frame_hash_func,frame_cmp,NULL))
  {
    printf("hash init failed\n");
    shutdown();
  }
}

/* allocates frame. If there are no more frame to allocate, 
evict then allocate. Returns allocated kernal virtual adress if sucessful
returns NULL otherwise. This function should not return NULL */
void *
allocate_frame(bool zero)
{
  uint8_t *kpage = NULL;
  if (zero)
    kpage = palloc_get_page(PAL_USER|PAL_ZERO);
  else
    kpage = palloc_get_page(PAL_USER);
  if (kpage == NULL)
  {
    frame_evict();
    if (zero)
      kpage = palloc_get_page(PAL_USER|PAL_ZERO);
    else
      kpage = palloc_get_page(PAL_USER);
  }
  //printf("kpage: %p\n",addr);

  insert_frame_entry(kpage);
  return kpage;
}

/*insert frame entry into hash table*/
void
insert_frame_entry (void *addr)
{
  struct thread *t = thread_current();
  struct frame_entry *f;
  f = malloc(sizeof(struct frame_entry));
  f->page_addr = addr;
  f->tid = t->tid;
  hash_insert(&frame_hash,&f->hash_elem);
}

/*evicts frame*/
void
release_frame(void *addr)
{
  //remove_frame_entry(addr);
  palloc_free_page(addr);
}

/*removes hash entry for frame table*/
void
remove_frame_entry (void *addr)
{
  struct frame_entry *f = frame_lookup(addr);
  hash_delete(&frame_hash,&f->hash_elem);
} 

/*frame eviction. We first decide the clock hand randomly, then from there,
we check every entry that are in frame and accessed bits is 0
This entry is deleted from hash table, inserted into swap disk, modify 
supplementary page table, modify pagedirectory and frees the frame.
If all elements have accesesd bit 1, we just pick a random frame to evict*/
void
frame_evict ()
{
  //printf("frame_evict()\n");
  int itr;
  bool flag = false;
  struct hash_iterator i;
  struct thread *t = thread_current();
  struct frame_entry *f =NULL;
  random_init(-1);
  int clock_pos = random_ulong() % hash_size(&frame_hash);
  size_t loc = 0;
  void *uaddr = NULL;
  hash_first (&i,&frame_hash);
  for (itr = 0; itr < clock_pos-1;itr++)
    hash_next(&i);
  while (hash_next (&i))
  {
    f = hash_entry(hash_cur(&i),struct frame_entry, hash_elem);
    uaddr = return_uaddr(t->sup_pt,f->page_addr);
    if (uaddr == NULL)
      continue;
    if (!pagedir_is_accessed(t->pagedir,uaddr))
    {
      hash_delete(&frame_hash,&f->hash_elem);
      loc = insert_swap_entry (f->page_addr);
      //printf("bitmap_loc: %d, %p\n",loc,uaddr);
      convert_to_swap(t->sup_pt,uaddr,loc);
      pagedir_clear_page(t->pagedir,uaddr);
      palloc_free_page (f->page_addr);
      flag = true;
      break;
    }
  }
  if (uaddr == NULL)
  {
    //printf("start\n");
    struct thread *og = thread_find(f->tid);
    uaddr = return_uaddr(og->sup_pt,f->page_addr);
    hash_delete(&frame_hash,&f->hash_elem);
    loc = insert_swap_entry (f->page_addr);
    //printf("bitmap_loc: %d, %p\n",loc,uaddr);
    convert_to_swap(og->sup_pt,uaddr,loc);
    pagedir_clear_page(og->pagedir,uaddr);
    palloc_free_page (f->page_addr);
    //printf("end\n");
    flag = true;
  }
  if (!flag)
  {
    uaddr = return_uaddr(t->sup_pt,f->page_addr);
    //printf("flag\n");
    hash_delete(&frame_hash,&f->hash_elem);
    loc = insert_swap_entry (f->page_addr);
    //printf("bitmap_loc: %d, %p\n",loc,uaddr);
    if (uaddr != NULL)
    {
      convert_to_swap(t->sup_pt,uaddr,loc);
    }
    if (uaddr != NULL)
      pagedir_clear_page(t->pagedir,uaddr);
    palloc_free_page (f->page_addr);
  }
}

/*necessray hash function element. Returns hashed value*/
unsigned
frame_hash_func (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct frame_entry *p = hash_entry (p_, struct frame_entry, hash_elem);
  return hash_bytes (&p->page_addr,sizeof(p->page_addr));
}

/*necessray hash function element. Returns true if b is bigger, false if 
a is bigger.*/
bool
frame_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct frame_entry *a = hash_entry (a_, struct frame_entry, hash_elem);
  const struct frame_entry *b = hash_entry (b_, struct frame_entry, hash_elem);
  return a->page_addr < b->page_addr;
}

/*necessray hash function element. Finds hash_entry with key "address"*/
struct frame_entry*
frame_lookup (void *address)
{
  struct frame_entry f;
  struct hash_elem *e;

  f.page_addr = address;
  e = hash_find(&frame_hash,&f.hash_elem);
  return e != NULL ? hash_entry(e,struct frame_entry,hash_elem) : NULL;
}


