#include "threads/thread.h"
#include <hash.h>
struct hash frame_hash;

/*structure in hash table for frame table*/
struct frame_entry
{
   void *page_addr;  			//kernel virtual adress
   tid_t tid;					//tid of process
   struct hash_elem hash_elem;  //hash element
};

void init_frame_table (void);
void *allocate_frame (bool zero);
void release_frame (void *addr);
void insert_frame_entry (void *addr);
void remove_frame_entry (void *addr);
void frame_evict (void);

unsigned frame_hash_func (const struct hash_elem *p_, void *aux UNUSED);
bool frame_cmp 
(const struct hash_elem *a_, const struct hash_elem *b_,void *aux UNUSED);
struct frame_entry* frame_lookup (void *address);

