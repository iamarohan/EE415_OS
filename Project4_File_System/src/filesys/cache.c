#include <list.h>
#include <string.h>
#include <stdio.h>

#include "threads/malloc.h"
#include "threads/interrupt.h"

#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/off_t.h"
#include "filesys/inode.h"

#include "devices/block.h"
#define INODE_MAGIC 0x494e4f44
static struct list buffer_cache;
static struct list_elem *clock_hand;
static int timer;

void 
cache_init(void)
{
  list_init(&buffer_cache);
  clock_hand = list_head(&buffer_cache);
  timer = 0;
}

void
cache_crt (block_sector_t start, block_sector_t sector)
{
  if (cache_find(sector) != NULL)
    return;
  struct cache_ent *ce = NULL;
  ce = calloc(1,sizeof *ce);
  ce->start = start;
  ce->data = NULL;
  ce->is_accessed = false;
  ce->is_dirty = false;
  ce->sector = sector;
  list_push_front (&buffer_cache,&ce->elem);
}

void
add_data_cache (block_sector_t start, block_sector_t sector_idx)
{
  //printf("add_data_cache start %d %d\n",start,sector_idx);
  //printf("%d\n",sizeof(block_sector_t));
  if ((list_size(&buffer_cache) >= 66) && (cache_find(sector_idx) == NULL))
    evict_cache();
  cache_crt(start,sector_idx);
  struct cache_ent *ce = cache_find(sector_idx);
  if (ce == NULL)
    PANIC("no entry like this before\n");
  ce->data = calloc(1,BLOCK_SECTOR_SIZE);
  block_read (fs_device, sector_idx, ce->data);
  ce->is_accessed = true;

  block_sector_t sector_next = sector_idx+1;
  struct inode_disk *d = malloc(BLOCK_SECTOR_SIZE);
  block_read (fs_device, sector_next, d);
  if ((INODE_MAGIC != d->magic) && (d == NULL))
  {
    if ((list_size(&buffer_cache) >= 66) && (cache_find(sector_next) == NULL))
      evict_cache();
    cache_crt(start,sector_next);
    struct cache_ent *sce = cache_find(sector_next);
    sce->data = calloc(1,BLOCK_SECTOR_SIZE);
    memcpy(sce->data,d,BLOCK_SECTOR_SIZE);
    sce->is_accessed = true;
  }
  free(d);
}

void
write_data (const uint8_t *buffer,off_t bytes_written, int sector_ofs, int chunk_size, block_sector_t sector)
{
  struct cache_ent *ce = cache_find (sector);
  if (ce == NULL)
    PANIC("ahhhhhhhhhhhh kill meeee\n");
  memcpy(ce->data+sector_ofs,buffer+bytes_written,chunk_size);
  ce->is_accessed = true;
  ce->is_dirty = true;
}

void
read_data(uint8_t *buffer,off_t bytes_read, int sector_ofs, int chunk_size, block_sector_t sector)
{
  struct cache_ent *ce = cache_find (sector);
  memcpy(buffer+bytes_read,ce->data+sector_ofs,chunk_size);
}

void
evict_cache (void)
{
  //printf("evict cache\n");
  struct cache_ent *ce;
  clock_hand = clock_hand->next;
  for(;;clock_hand = clock_hand->next)
    {
      //printf("looop\n");
      ce = list_entry (clock_hand, struct cache_ent, elem);
      if (clock_hand->next->next == NULL)
      {
        clock_hand = list_front(&buffer_cache);
      }
      //printf("ce->start: %d, %d\n",ce->start, FREE_MAP_SECTOR);
      if (ce->start == FREE_MAP_SECTOR)
        continue;
      if (!ce->is_accessed)
      {
        if (ce->is_dirty)
        {
          //printf("here\n");
          block_write (fs_device,ce->sector,ce->data);
        }
        if (ce->data != NULL)
        //free(ce->data);
        list_remove(&ce->elem);
        //free(ce);
        //printf("end evict cache\n");
        return;
      }
      if (ce->is_accessed)
        ce->is_accessed = false;    
    }
  
}

void
write_dirty (void)
{
  //printf("write dirty\n");
  if (list_empty(&buffer_cache))
    return;
  timer++;
  if (timer > 4)
  {
    struct cache_ent *ce;
    struct list_elem *init;
    for(init = list_front(&buffer_cache);init->next != NULL;init = init->next)
      {
        ce = list_entry (init, struct cache_ent, elem);
        if (ce->is_dirty == true)
        {
	  block_write(fs_device,ce->sector,ce->data);
          ce->is_dirty = false;
        }
      }
    timer = 0;
  }
}

bool
is_cached (block_sector_t sector)
{
  struct cache_ent *ce = cache_find(sector);
  if (ce->data == NULL)
    return false;
  return true;
} 

struct cache_ent*
cache_find (block_sector_t sector)
{
  //printf("cache_find start %d\n",sector);
  if (list_empty(&buffer_cache))
  {
    //printf("cache_find end nULL\n");
    return NULL;
  }
  struct cache_ent *ce;
  struct list_elem *init;
  for(init = list_front(&buffer_cache);init->next != NULL;init = init->next)
    {
      ce = list_entry (init, struct cache_ent, elem);
      if (ce->sector == sector)
      {
        //printf("cache_find end\n");
        return ce;
      }
    }
  //printf("cache_find end NULL\n");
  return NULL;
}


