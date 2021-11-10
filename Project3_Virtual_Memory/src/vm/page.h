#include "threads/thread.h"
#include <hash.h>

//structure for the hash list for supplementary page table
struct sup_pte
{
  void *vaddr;				//virtual addr
  void *paddr;				//physical addr
  bool swap;					//true if in swap
  bool writable;			//true if writable
  bool mapped;				//true if mapped file
  int  fd;					  //file descriptor
  int  file_order;   //order of file (used for mmap)
  int  zero_count;   //number of zeros (used for mmap)
  struct file *file; //pointer to mapped file
  size_t bitmap_loc;			//bitmap loc of swap table
  struct hash_elem hash_elem;	//hash element
};

void init_sup_pagedir(struct hash *hash);
void create_sup_pte 
(struct hash *hash, void *vaddr, void *paddr,bool writable);
void
mapped_file (struct hash *hash, void *vaddr, int fd, int file_order, 
  int zero_count,struct file *file);
struct file*
seek_file(struct hash *hash, void *vaddr);
void set_paddr(struct hash *hash, void *vaddr, void* paddr);
void *return_valid_info(struct hash *hash, void *vaddr);
void *return_paddr (struct hash *hash, void *vaddr);
void *return_uaddr(struct hash *hash, void *paddr);
void *return_vaddr_mapped (struct hash *hash, int fd, int order);
int  return_fd (struct hash *hash, void *vaddr);
int  return_zero_count (struct hash *hash, void *vaddr);
size_t return_bitmap_loc (struct hash *hash, void *vaddr);
void copy_sup_pd(struct hash *c_hash, struct hash *p_hash);
void copy_pagedir(struct hash *hash, uint32_t *child_pd);
void convert_to_swap (struct hash *hash, void *vaddr, size_t bitmap_loc);
void delete_sup_pte (struct hash *hash, void *vaddr);
bool is_writable(struct hash *hash, void *vaddr);
bool is_mapped (struct hash *hash, void *vaddr);
bool is_swap (struct hash *hash, void *vaddr);
void destroy_sup_pte(struct hash *hash);
unsigned sup_pt_hash (const struct hash_elem *pte, void *aux UNUSED);
bool sup_pt_cmp 
(const struct hash_elem *a_, const struct hash_elem *b_,void *aux UNUSED);

struct sup_pte* sup_pte_lookup (struct hash *hash,void *vaddr);

