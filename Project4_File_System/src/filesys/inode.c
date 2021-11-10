#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
#include "devices/shutdown.h"

#include "filesys/inode.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"

#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define NUM_DIR_BLOCK 12
#define NUM_INDIR_BLOCK 112
#define NUM_DBINDIR_BLOCK 1


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

struct indir_block
  {
    block_sector_t sectors[128];
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  //printf("inode_create start %d\n",sector);
  struct inode_disk *disk_inode = NULL;
  bool success = false;
  ASSERT (length >= 0);
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  
  disk_inode = calloc (1, sizeof *disk_inode);

  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      //printf("open: %d, %d\n",sector,sectors);
      if (sector == 0)
      {
        if (free_map_allocate (sectors, &disk_inode->start)) 
        {
          disk_inode->sectors[0] = disk_inode->start;
          if (sectors > 1) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              for (i = 1; i < sectors; i++) 
              {
                free_map_allocate (1, &disk_inode->sectors[i]);
                block_write (fs_device, disk_inode->sectors[i], zeros);
              }
            }
        }
      }
      else
      {
       //printf("create sectors: %d\n",sectors);
        if (sectors > 0) 
        {
          static char zeros[BLOCK_SECTOR_SIZE];
          size_t i;
          int sz;
          size_t index = 0;
          for (i = 0; i < sectors; i++) 
          {
            //printf("I am index: %d\n",index);
            if (i < NUM_DIR_BLOCK)
            {
              free_map_allocate (1, &disk_inode->sectors[index]);
              block_write (fs_device, disk_inode->sectors[index], zeros);
            }
            //indirect pointer
            else if ((i >= NUM_DIR_BLOCK) || (i < (NUM_INDIR_BLOCK*128+NUM_DIR_BLOCK)))
            {
              struct indir_block *indir_block;
              ASSERT (sizeof *indir_block == BLOCK_SECTOR_SIZE);
              indir_block = calloc (1, sizeof *indir_block);
              sz = i - 12;
              int div = sz / 128;
              //printf("div: %d\n",div);
              if (disk_inode->sectors[index] == 0)
              	free_map_allocate (1, &disk_inode->sectors[index]);
              for (;;sz++)
              {
                int rem = sz % 128;
	        if ((sz/128 != div) || (i >= sectors))
                  break;
                free_map_allocate(1,&indir_block->sectors[rem]);
                block_write(fs_device, indir_block->sectors[rem], zeros); 
                //printf("sz: %d, rem: %d, actual sector: %d\n", sz,rem, indir_block->sectors[rem]);
                i++;
              }
              block_write(fs_device, disk_inode->sectors[index],indir_block);
              free(indir_block);
              i--;
              //shutdown();
            }
            //for larger files, allocate an entire double pointer
            else
            {
              if (index != 124)
                PANIC("file is too large wha\n");
              struct indir_block *indir_block = calloc (1, sizeof *indir_block);
              if (disk_inode->sectors[index] == 0)
              	free_map_allocate (1, &disk_inode->sectors[index]);
              int ddp_itr;
              int ddp_itr_2;
              for (ddp_itr=0;ddp_itr < 20; ddp_itr++)
              {
                free_map_allocate(1,&indir_block->sectors[ddp_itr]);
                struct indir_block *d_indir = calloc(1,sizeof *indir_block);
                for (ddp_itr_2=0;ddp_itr_2 < 128; ddp_itr_2++)
                {
                  free_map_allocate(1,&d_indir->sectors[ddp_itr_2]);
                  block_write(fs_device,d_indir->sectors[ddp_itr_2],zeros);
                  i++;
                }
                block_write(fs_device,indir_block->sectors[ddp_itr],d_indir);
                free(d_indir);
              }
              block_write(fs_device, disk_inode->sectors[index],indir_block);
              free(indir_block);
            }
            index++;
          }
        }
      }
      disk_inode->start = disk_inode->sectors[0];
      success = true;
      block_write (fs_device, sector, disk_inode);
      free (disk_inode); 
    }
  //printf("inode_create end\n");
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;
  //printf("open sector: %d\n",sector);
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }
  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
  {
    return NULL;
  }
  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->sector, &inode->data);
  //printf("inode_open_done\n");
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  //printf("inode_close\n");
  //printf("inode close %d, %d, %d\n",inode->sector,inode->data.start,bytes_to_sectors (inode->data.length));
  
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          free_map_release (inode->data.start,
                            bytes_to_sectors (inode->data.length)); 
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  if (inode->sector != 0)
  {
    //printf("inode_read_at: %d\n",inode->sector);
    //printf("offset: %d, size: %d\n", offset,size);
  }
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  block_sector_t sector_idx;
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      
      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;
      
      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      //printf("%d\n",chunk_size);
      //printf("%d\n",size);
      if (chunk_size <= 0)
        break;
      if (1)
      {
        block_sector_t byte_sector = offset/BLOCK_SECTOR_SIZE;
        //printf("byte_sector: %d\n",byte_sector);
        if (byte_sector < NUM_DIR_BLOCK)
          sector_idx = inode->data.sectors[byte_sector];
        else if ((byte_sector >= NUM_DIR_BLOCK) || (byte_sector < (NUM_INDIR_BLOCK*128+NUM_DIR_BLOCK)))
        {
          //printf("second section\n");
          int sz = byte_sector-12;
          int div = sz / 128;
          int rem = sz % 128;
          sector_idx = inode->data.sectors[div+12];
          //printf("div: %d, rem: %d\n",div+12,rem);
          struct indir_block *indir_block = calloc(1,BLOCK_SECTOR_SIZE);
          if (cache_find(sector_idx) == NULL)
            add_data_cache(inode->data.start,sector_idx);
          read_data((void *)indir_block,0,0,BLOCK_SECTOR_SIZE,sector_idx);
          //block_read(fs_device,sector_idx,indir_block);
          sector_idx = indir_block->sectors[rem];
          //printf("indirect sector_idx: %d\n",sector_idx);
          free(indir_block);
        }
        else
        {
          printf("third section\n");
          int ddp = byte_sector - (NUM_INDIR_BLOCK*128+NUM_DIR_BLOCK);
          int div_ddp = ddp / 128;
          int rem_ddp = ddp % 128;
          struct indir_block *indir_block = calloc(1,BLOCK_SECTOR_SIZE);
          block_read(fs_device,inode->data.sectors[124],indir_block);
          struct indir_block *ddp_block = calloc(1,BLOCK_SECTOR_SIZE);
          block_read(fs_device,indir_block->sectors[div_ddp],ddp_block);
          sector_idx = ddp_block->sectors[rem_ddp];
          free(indir_block);
          free(ddp_block);
        }
      }
      //else
      //  sector_idx = byte_to_sector(inode,offset);
      //printf("open: %d\n",sector_idx);
      //printf("cached if condition\n");
      if (cache_find(sector_idx) == NULL)
      {
        //printf("cached %d\n",sector_idx);
      	add_data_cache (inode->data.start,sector_idx);
      }
      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          read_data(buffer,bytes_read,0,BLOCK_SECTOR_SIZE,sector_idx);
        }
      else 
        {
          read_data(buffer,bytes_read,sector_ofs,chunk_size,sector_idx);
        }
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  if (inode->sector != 0)
  {
    //printf("inode_write_at: %d\n",(int)inode->sector);
    //printf("offset: %d, size %d\n", (int)offset,(int) size);
  }
  //printf("inode_write_at: %d\n",(int)inode->sector);
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  block_sector_t sector_idx = 0;
  if (inode->deny_write_cnt)
    return 0;
  while (size > 0) 
    {
      if (1)
      {
        //printf("inode_length: %d, %d\n",(int)inode_length(inode), (int)size);
        block_sector_t byte_sector = (offset)/BLOCK_SECTOR_SIZE;
        int sz = byte_sector-12;
        int div = sz / 128;
        int div_prem = div;
        int rem = sz % 128;
        int og_max_sector = (inode->data.length-1)/BLOCK_SECTOR_SIZE; 
        int sectors = byte_sector;
        static char zeros[BLOCK_SECTOR_SIZE];
        sectors = sectors - og_max_sector;
        while (offset > inode_length(inode))
        {
          char zero = 0;
          //printf("use: %d\n",offset-inode_length(inode));
          inode_write_at (inode,&zero,1,inode_length(inode));
        }
        //printf("byte_sector: %d\n",byte_sector);
        if (byte_sector < NUM_DIR_BLOCK)
        {
          sector_idx = inode->data.sectors[byte_sector];
          //file extension
	  if (sector_idx == 0)
          {
            free_map_allocate (1, &inode->data.sectors[byte_sector]);
            int size_min = size < BLOCK_SECTOR_SIZE ? size : BLOCK_SECTOR_SIZE;
            int increase = size_min < (BLOCK_SECTOR_SIZE-(offset % BLOCK_SECTOR_SIZE)) ? size_min : 						(BLOCK_SECTOR_SIZE-(offset % BLOCK_SECTOR_SIZE));
            inode->data.length += increase;
            sector_idx = inode->data.sectors[byte_sector];
            if (byte_sector == 0)
              inode->data.start = inode->data.sectors[byte_sector];
            //printf("increase: %d\n",increase);
          }
          else if (inode_length(inode) < offset+size)
          {
            int size_min = size < BLOCK_SECTOR_SIZE ? size : BLOCK_SECTOR_SIZE;
            int increase = size_min < (BLOCK_SECTOR_SIZE-(offset % BLOCK_SECTOR_SIZE)) ? size_min : 						(BLOCK_SECTOR_SIZE-(offset % BLOCK_SECTOR_SIZE));
            //printf("increase: %d\n",increase);
            inode->data.length += increase;
          }
        }
        else if ((byte_sector >= NUM_DIR_BLOCK) && (byte_sector < (NUM_DIR_BLOCK + 128*NUM_INDIR_BLOCK)))
        {
          
          //printf("off, og: %d, %d\n",(int) div+12, (int) og_max_sector);
          //printf("rem: %d\n",(int) rem);
          sector_idx = inode->data.sectors[div+12];
          int flag = 0;
          //extend to a new indirect pointer
          if (sector_idx == 0)
          {
            //printf("extension1 %d\n",div+12);
            //number of sectors we need to allocate
            //printf("sector %d\n",sectors);
            if (sectors > 0)
            {
                struct indir_block *indir_block2 = calloc(1,BLOCK_SECTOR_SIZE);
                //div = i / 128;
                if (inode->data.sectors[div+12] == 0)
                {
                  //printf("extention 0\n");
              	  free_map_allocate (1,&inode->data.sectors[div+12]);
                  free_map_allocate(1,&indir_block2->sectors[rem]);
                  block_write(fs_device, indir_block2->sectors[rem], zeros);
                  block_write(fs_device, inode->data.sectors[div+12],indir_block2);
                  int size_min = size < BLOCK_SECTOR_SIZE ? size : BLOCK_SECTOR_SIZE;
                  int increase = size_min < (BLOCK_SECTOR_SIZE-(offset % BLOCK_SECTOR_SIZE)) ? size_min : 						(BLOCK_SECTOR_SIZE-(offset % BLOCK_SECTOR_SIZE));
                  inode->data.length += increase;
                  //printf("increase: %d\n",increase);
                  flag = 1;
                }
                free(indir_block2);
             }
            sector_idx = inode->data.sectors[div_prem+12];
           }
          struct indir_block *indblock = calloc(1,BLOCK_SECTOR_SIZE);
          struct inode_disk *disk_inode = &inode->data;
          /*if (cache_find (sector_idx) == NULL)
            add_data_cache(inode->data.start,sector_idx);
          read_data((void *)indblock,0,0,BLOCK_SECTOR_SIZE,sector_idx);*/
          block_read(fs_device,sector_idx,indblock);
	  sector_idx = indblock->sectors[rem];
          if (sector_idx == 0)
          {
            //printf("extension 6\n");
            free_map_allocate(1,&indblock->sectors[rem]);
            int size_min = size < BLOCK_SECTOR_SIZE ? size : BLOCK_SECTOR_SIZE;
            int increase = size_min < (BLOCK_SECTOR_SIZE-(offset % BLOCK_SECTOR_SIZE)) ? size_min : 						(BLOCK_SECTOR_SIZE-(offset % BLOCK_SECTOR_SIZE));
            //printf("increase: %d\n",increase);
            inode->data.length += increase;
            block_write(fs_device, disk_inode->sectors[div_prem+12],indblock);
            sector_idx = indblock->sectors[rem];
          }
          else if ((inode_length(inode) < (offset+size)) && (flag == 0))
            {
              //printf("extension5 %d\n",(int)offset % BLOCK_SECTOR_SIZE);
              int size_min = size < BLOCK_SECTOR_SIZE ? size : BLOCK_SECTOR_SIZE;
              int increase = size_min < (BLOCK_SECTOR_SIZE-(offset % BLOCK_SECTOR_SIZE)) ? size_min : 						(BLOCK_SECTOR_SIZE-(offset % BLOCK_SECTOR_SIZE));
              //printf("increase: %d\n",increase);
              inode->data.length += increase;
            }
          //printf("sector_idx: %d\n",(int) sector_idx);
          free(indblock);
        }
        //I don't zero out for this one.
        else
        {
          /*printf("byte_sector: %d\n",byte_sector);
          static char zeros[BLOCK_SECTOR_SIZE];
          struct inode_disk *disk_inode = &inode->data;
          struct indir_block *indir_block1 = calloc (1, sizeof *indir_block);
          if (disk_inode->sectors[124] == 0)
          {
            free_map_allocate (1, &disk_inode->sectors[124]);
            disk_write(fs_device,disk_inode->sectors[124],indir_block1);
          }
          int ddp_itr = 0;
          int div = byte_sector/128;
          int ddp_itr_2 = 0;
          int rem = byte_sector%128;
          
	  disk_read(fs_device,disk_inode->sectors[124],indir_block1);
          if (indir_block1->sectors[0] == 0)
          {
            
          }


          for (ddp_itr=0;ddp_itr < 20; ddp_itr++)
          {
            free_map_allocate(1,&indir_block->sectors[ddp_itr]);
            struct indir_block *d_indir = calloc(1,sizeof *indir_block);
            for (ddp_itr_2=0;ddp_itr_2 < 128; ddp_itr_2++)
            {
              free_map_allocate(1,&d_indir->sectors[ddp_itr_2]);
              block_write(fs_device,d_indir->sectors[ddp_itr_2],zeros);
            }
            block_write(fs_device,indir_block->sectors[ddp_itr],d_indir);
            free(d_indir);
          }
          block_write(fs_device, disk_inode->sectors[124],indir_block);
          free(indir_block);
          int ddp = byte_sector - (NUM_INDIR_BLOCK*128+NUM_DIR_BLOCK);
          int div_ddp = ddp / 128;
          int rem_ddp = ddp % 128;
          struct indir_block *ddp_block_2 = calloc(1,BLOCK_SECTOR_SIZE);
          block_read(fs_device,inode->data.sectors[124],ddp_block_2);
          struct indir_block *ddp_block = calloc(1,BLOCK_SECTOR_SIZE);
          block_read(fs_device,ddp_block_2->sectors[div_ddp],ddp_block);
          sector_idx = ddp_block->sectors[rem_ddp];
          free(ddp_block_2);
          free(ddp_block);*/
        }
      }
      //else
      //{
      //  sector_idx = byte_to_sector(inode,offset);
      //}
      /* Sector to write, starting byte offset within sector. */
      
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      //printf("write: %d\n",sector_idx);
      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;
      //printf("sector_left: %d,inode_left: %d\n",sector_left,inode_left);

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      //printf("chunk_size: %d\n",chunk_size);
      if (chunk_size <= 0)
        break;
      if (cache_find(sector_idx) == NULL)
      {
        //printf("cached %d\n",sector_idx);
      	add_data_cache (inode->data.start,sector_idx);
      }
      //printf("chunk_size: %d\n",chunk_size);
      if ((sector_ofs == 0) && (chunk_size == BLOCK_SECTOR_SIZE))
        write_data(buffer,bytes_written,sector_ofs,chunk_size,sector_idx);
      else 
        write_data(buffer,bytes_written,sector_ofs,chunk_size,sector_idx);
      //printf("chunk_size: %d\n",chunk_size);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  block_write (fs_device,inode->sector, &inode->data);
  //printf("bytes_written: %d\n",bytes_written);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
