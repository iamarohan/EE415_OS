#include <list.h>

#include "devices/block.h"
#include "filesys/off_t.h"

//list element structure for buffer cache
struct cache_ent
  {
    struct list_elem elem;	//list element
    uint8_t *data;		//data stored in block
    block_sector_t start;	//sector of inode
    block_sector_t sector;	//sector of block
    bool is_accessed;		//accessed bit
    bool is_dirty;		//dirty bit
  };

void cache_init(void);
void cache_crt (block_sector_t start, block_sector_t sector);
void add_data_cache (block_sector_t start, block_sector_t sector_idx);
void write_data (const uint8_t *buffer,off_t bytes_written, int sector_ofs, int chunk_size, block_sector_t sector);
bool is_cached (block_sector_t sector);
void evict_cache (void);
void write_dirty (void);
void read_data(uint8_t *buffer,off_t bytes_read, int sector_ofs, int chunk_size, block_sector_t sector);
struct cache_ent* cache_find (block_sector_t sector);
