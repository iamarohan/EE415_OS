#include "threads/thread.h"
#include "devices/block.h"
#include <hash.h>

//entry for hash list for swap_table
struct st_entry
{
   void *vaddr;					//kernel virtual address of the page that 
								//is evicted to swap table
   size_t bitmap_loc;			//bitmap location of this swap element
   struct hash_elem hash_elem;  //hash element
};


void init_swap_table (void);
size_t insert_swap_entry (void *vaddr);
void remove_swap_entry (size_t bitmap_loc, void *new_addr);
unsigned swap_hash_func (const struct hash_elem *p_, void *aux UNUSED);
bool swap_cmp (const struct hash_elem *a_, 
	const struct hash_elem *b_,void *aux UNUSED);
struct st_entry* st_entry_lookup (size_t bitmap_loc);


