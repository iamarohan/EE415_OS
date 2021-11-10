#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/pagedir.h"

#include "vm/page.h"
#include "vm/swap.h"

#include "devices/shutdown.h"

#include <hash.h>
#include <stdio.h>


/*Initialize supplementary page directory*/
void
init_sup_pagedir(struct hash *hash)
{
  hash_init(hash,sup_pt_hash,sup_pt_cmp,NULL);
}

/*Creates an entry of supplementary page table, and stores it in the hash
table.*/
void
create_sup_pte (struct hash *hash, void *vaddr, void *paddr,bool writable)
{
  struct sup_pte *p = sup_pte_lookup(hash,vaddr);
  //if there already is an entry, just change writable. This is needed
  //for child processes. 
  //printf("ctsup_pt:%p\n",vaddr);
  if (p != NULL)
  {
    p->writable = writable;
    return;
  }
  struct sup_pte *s = malloc(sizeof(struct sup_pte));
  if (s==NULL)
    PANIC("no memory for sup_pte");
  s->vaddr = vaddr;
  s->paddr = paddr;
  s->writable = writable;
  s->swap = false;
  s->mapped = false;
  s->fd = -1;
  s->file_order = -1;
  s->zero_count = 0;
  s->file = NULL;
  hash_insert(hash,&s->hash_elem);
  //printf("create_s_pte: %p\n",vaddr);
}

void
mapped_file (struct hash *hash, void *vaddr, int fd,int file_order, int zero_count,struct file *file)
{
  struct sup_pte *p = sup_pte_lookup(hash,vaddr);
  if (p == NULL)
  {
    PANIC("create first\n");
  }
  
  p->mapped = true;
  p->fd = fd;
  p->file_order = file_order;
  p->zero_count = zero_count;
  p->file = file;
}

struct file*
seek_file(struct hash *hash, void *vaddr)
{
  struct sup_pte *p = sup_pte_lookup(hash,vaddr);
  return p->file;
}

/*chagnes paddr of supplementary page table entry with key vaddr to paddr*/
void
set_paddr(struct hash *hash, void *vaddr, void* paddr)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  s->paddr = paddr;
}

/*returns vaddr of hash element with key vaddr*/
void *
return_valid_info(struct hash *hash, void *vaddr)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  if (s == NULL)
  { 
    //printf("entry not valid\n");
    return NULL;
  }
  return vaddr;
}

void *
return_vaddr_mapped (struct hash *hash, int fd, int order)
{
  struct hash_iterator i;
  hash_first(&i,hash);
  while (hash_next(&i))
  {
    struct sup_pte *s = hash_entry (hash_cur(&i),struct sup_pte,hash_elem);
    if (s->fd == fd)
    {
      if (s->file_order == order)
        return s->vaddr;
    }
  }
  return NULL;
}

/*delete supplementary page table entry sup_pte*/
void 
delete_sup_pte (struct hash *hash, void *vaddr)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  hash_delete(hash,&s->hash_elem);
}

/*returns the paddr of the supplementary page table entry with key vaddr*/
void *
return_paddr (struct hash *hash, void *vaddr)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  if (s == NULL)
    return NULL;
  else
    return s->paddr;
}

/*returns the bitmap_loc of supplementary page table entry with key vaddr*/
size_t
return_bitmap_loc (struct hash *hash, void *vaddr)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  if (s == NULL)
    PANIC("ahjhhhhhh!");
  else
    return s->bitmap_loc;
}

/*returns the uaddr of a supplementary page table entry with paddr paddr*/
void *
return_uaddr(struct hash *hash, void *paddr)
{
  //printf("return_uaddr\n");
  struct hash_iterator i;
  hash_first(&i,hash);
  while (hash_next(&i))
  {
    struct sup_pte *s = hash_entry (hash_cur(&i),struct sup_pte,hash_elem);
    if (paddr == s->paddr)
      return s->vaddr;
  }
  return NULL;
}

/*returns the fd of a supplementary page table entry with paddr paddr*/
int
return_fd (struct hash *hash, void *vaddr)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  if (s == NULL)
    PANIC("ahjhhhhhh!");
  else
    return s->fd;
}

int 
return_zero_count (struct hash *hash, void *vaddr)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  if (s == NULL)
    PANIC("ahjhhhhhh!");
  else
    return s->zero_count;
}

/*copies the supplemntary page table p_hash to c_hash*/
void
copy_sup_pd(struct hash *c_hash, struct hash *p_hash)
{
  struct hash_iterator i;
  hash_first(&i,p_hash);
  while (hash_next(&i))
  {
    struct sup_pte *s = hash_entry (hash_cur(&i),struct sup_pte,hash_elem);
    create_sup_pte (c_hash, s->vaddr, s->paddr,s->writable);
    if (s->swap)
      convert_to_swap(c_hash,s->vaddr,s->bitmap_loc);
  }
}

/*copies page_directory of one process to another process*/
void
copy_pagedir(struct hash *hash, uint32_t *child_pd)
{
  struct hash_iterator i;
  hash_first(&i,hash);
  while (hash_next(&i))
  {
    struct sup_pte *s = hash_entry (hash_cur(&i),struct sup_pte,hash_elem);
    if (!s->swap)
      pagedir_set_page(child_pd,s->vaddr,s->paddr,s->writable);
  }
}

/*when an frame is evicted to swap, the supplementary keeps track of its
bitmap_loc of swap table and sets swap element to true. This notifies
us that this entry is no longer in frame table*/
void
convert_to_swap (struct hash *hash, void *vaddr, size_t bitmap_loc)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  if (s==NULL)
    PANIC("no sup entry to convert");
  s->paddr = 0x00;
  s->swap = true;
  s->bitmap_loc = bitmap_loc;
}

/*returns true if supplementary page table entry with key vaddr is in swap
false otherwise*/
bool
is_swap (struct hash *hash, void *vaddr)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  if (s== NULL)
    PANIC("ahhhhhhhhh!");
  else
    return s->swap;
}

/*returns true is supplementary page table entry with key vaddr is writable*/
bool
is_writable(struct hash *hash, void *vaddr)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  return s->writable;
}

/*returns true is supplementary page table entry with key vaddr is mapped*/
bool
is_mapped (struct hash *hash, void *vaddr)
{
  struct sup_pte *s = sup_pte_lookup(hash,vaddr);
  return s->mapped;
}

void
destroy_sup_pte(struct hash *hash)
{
  struct hash_iterator i;
  hash_first(&i,hash);
  while (hash_next(&i))
  {
    struct sup_pte *s = hash_entry (hash_cur(&i),struct sup_pte,hash_elem);
    if (s->swap)
      remove_swap_entry(s->bitmap_loc,NULL);
    delete_sup_pte(hash,s->vaddr);
  } 
}

/*necessray hash function element. Returns hashed value*/
unsigned
sup_pt_hash (const struct hash_elem *pte, void *aux UNUSED)
{
  const struct sup_pte *p = hash_entry (pte, struct sup_pte, hash_elem);
  return hash_bytes (&p->vaddr,sizeof(p->vaddr));
}

/*necessray hash function element. Returns true if b is bigger, false if 
a is bigger.*/
bool
sup_pt_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct sup_pte *a = hash_entry (a_, struct sup_pte, hash_elem);
  const struct sup_pte *b = hash_entry (b_, struct sup_pte, hash_elem);
  return a->vaddr < b->vaddr;
}

/*necessray hash function element. Finds hash_entry with key "address"*/
struct sup_pte*
sup_pte_lookup (struct hash *hash,void *vaddr)
{
  struct sup_pte s;
  struct hash_elem *e;

  s.vaddr = vaddr;
  e = hash_find(hash,&s.hash_elem);
  return e != NULL ? hash_entry(e,struct sup_pte,hash_elem) : NULL;
}

