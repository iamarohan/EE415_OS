#include "threads/thread.h"
#include "filesys/off_t.h"
#include <hash.h>

bool in_load;

/*Entry for a table that manages lazy loading*/
struct lazy_ent
{
  void *p_vaddr;			//the upage the start of an executable file is to 
  							//to be loaded to
  void *vaddr;				//addr of the virtual adresses executable file
  							//should be loaded to
  char *file_name;			//name of executable file
  uint32_t read_bytes;		//number of bytes executable file should read
  uint32_t zero_bytes;		//number of zeros loaded executable file has
  bool writable;			//is the file is writable
  off_t ofs;				//offset of the executable file read
  struct hash_elem hash_elem;  //hash element
};

void init_lazy(struct hash *hash);
void create_lazy_entry(struct hash *hash, void* p_vaddr,void *vaddr,
  char *file_name, uint32_t read_bytes, uint32_t zero_bytes, bool writable,
  off_t ofs);
void allocate_exec_file (struct hash *hash, void *vaddr);
struct lazy_ent*child_lookup (struct hash *hash,void *p_vaddr);
bool is_lazy (struct hash *hash, void *vaddr);
void print_all (struct hash *hash);
unsigned lazy_hash (const struct hash_elem *pte, void *aux UNUSED);
bool lazy_cmp (const struct hash_elem *a_, 
	const struct hash_elem *b_,void *aux UNUSED);
struct lazy_ent* lazy_lookup (struct hash *hash,void *vaddr);
