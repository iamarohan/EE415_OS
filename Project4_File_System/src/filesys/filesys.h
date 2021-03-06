#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "filesys/directory.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
bool filesys_create_sub (const char *name, off_t initial_size, struct dir *og_dir);
struct file *filesys_open (const char *name);
struct file *filesys_open_sub (const char *name, struct dir *og_dir);
bool filesys_remove (const char *name);
bool filesys_remove_sub (const char *name, struct dir *og_dir);
#endif /* filesys/filesys.h */
