#include <hash.h>
#include <stdio.h>
#include <string.h>
#include <round.h>

#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/pagedir.h"

#include "vm/lazy.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

#include "devices/shutdown.h"

#include "filesys/off_t.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

/*initialized table to manage lazy_loading*/
void
init_lazy(struct hash *hash)
{
  hash_init(hash,lazy_hash,lazy_cmp,NULL);
}

/*create an entry for the lazy_loading management table*/
void
create_lazy_entry(struct hash *hash,void *p_vaddr ,void *vaddr,
  char *file_name,uint32_t read_bytes, uint32_t zero_bytes, 
  bool writable,off_t ofs)
{
  //printf("crt: %p\n",vaddr);
  struct lazy_ent *s = malloc(sizeof(struct lazy_ent));
  s->file_name = (char *) malloc(strnlen(file_name,100));
  s->p_vaddr = p_vaddr;
  s->vaddr = vaddr;
  strlcpy(s->file_name,file_name,strnlen(file_name,100)+1);
  s->read_bytes = read_bytes;
  s->zero_bytes = zero_bytes;
  s->writable = writable;
  s->ofs = ofs;
  hash_insert(hash,&s->hash_elem);
}

/*load executable file that was not loaded at initialization*/
void
allocate_exec_file (struct hash *hash, void *vaddr)
{
  //printf("allocate_exec\n");
  void *page = (void *) ROUND_DOWN ((uintptr_t) vaddr, 4096);
  struct thread *t = thread_current();
  struct lazy_ent *s = lazy_lookup(hash,page);
  struct lazy_ent *l = lazy_lookup(hash,s->p_vaddr);
  void *upage = l->vaddr;
  size_t read_bytes = l->read_bytes;
  size_t zero_bytes = l->zero_bytes;
  in_load = true;
  struct file *file = filesys_open(l->file_name);
  in_load = false;
  file_seek(file,l->ofs);
  while (read_bytes > 0 || zero_bytes > 0)
  {
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    uint8_t *kpage = allocate_frame(false);

    file_read (file, kpage, page_read_bytes);

    memset (kpage + page_read_bytes, 0, page_zero_bytes);

    create_sup_pte(t->sup_pt,upage,kpage,l->writable);

    pagedir_set_page (t->pagedir,upage,kpage,l->writable);

    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;

    upage += PGSIZE;
  }
  file_close (file);
  void *save = l->vaddr;
  struct lazy_ent *del = child_lookup(t->lazy,save);
  while (del)
  {
    hash_delete(t->lazy,&del->hash_elem);
    del = child_lookup(t->lazy,save);
  }
  
  //printf("lazy_done: %p\n",l->vaddr);
}

/*lookup the parent entry (which is the one that has the vaddr file should
start loading at)*/
struct lazy_ent*
child_lookup (struct hash *hash,void *p_vaddr)
{
  struct lazy_ent s;
  struct hash_elem *e;

  s.vaddr = p_vaddr;
  e = hash_find(hash,&s.hash_elem);
  return e != NULL ? hash_entry(e,struct lazy_ent,hash_elem) : NULL;
}

/*check if an vaddr should be loaded lazily*/
bool
is_lazy (struct hash *hash, void *vaddr)
{
  void *page = (void *)ROUND_DOWN ((uintptr_t) vaddr, 4096);
  //printf("is_lazy: %p\n", page);
  bool yes_or_no = false;
  struct lazy_ent *s = lazy_lookup(hash,page);
  if (s != NULL)
    yes_or_no = true;
  return yes_or_no;
}

/*print everything in lazy loading management table. */
void
print_all (struct hash *hash)
{ 
  struct hash_iterator i;
  hash_first(&i,hash);
  while (hash_next(&i))
  {
    struct lazy_ent *s = hash_entry (hash_cur(&i),struct lazy_ent,hash_elem);
    struct lazy_ent *ck = lazy_lookup(hash,s->vaddr);
    if (ck != NULL)
      printf("%p\n",ck->vaddr);
  }
}

/*necessray hash function element. Returns hashed value*/
unsigned
lazy_hash (const struct hash_elem *pte, void *aux UNUSED)
{
  const struct lazy_ent *p = hash_entry (pte, struct lazy_ent, hash_elem);
  return hash_bytes (&p->vaddr,sizeof(p->vaddr));
}

/*necessray hash function element. Returns true if b is bigger, false if 
a is bigger.*/
bool
lazy_cmp (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct lazy_ent *a = hash_entry (a_, struct lazy_ent, hash_elem);
  const struct lazy_ent *b = hash_entry (b_, struct lazy_ent, hash_elem);
  return a->vaddr < b->vaddr;
}

/*necessray hash function element. Finds hash_entry with key "address"*/
struct lazy_ent*
lazy_lookup (struct hash *hash,void *vaddr)
{
  struct lazy_ent s;
  struct hash_elem *e;

  s.vaddr = vaddr;
  e = hash_find(hash,&s.hash_elem);
  return e != NULL ? hash_entry(e,struct lazy_ent,hash_elem) : NULL;
}

