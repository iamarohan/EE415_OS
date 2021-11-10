#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "threads/thread.h"
#include "filesys/directory.h"
#include <list.h>
#define READDIR_MAX_LEN 14

typedef int pid_t;
struct semaphore exec_sema;
struct exit_pair{
  tid_t tid;
  int status;
  struct list_elem elem;
};

struct dir_sector{
  block_sector_t sector;	//inode sector of open directory
  block_sector_t prev_sector;   //parent directory inode sector
  struct list_elem elem;	//list element
};

void syscall_init (void);
//syscall functions
void halt (void);
void exit (int status);
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);

int filesize (int fd);

int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

//project 4
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char name[READDIR_MAX_LEN + 1]);
bool isdir (int fd);
int inumber (int fd);

//function that help syscall functions
void check_esp(void *esp);
struct file *find_file (int fd);
struct file *find_file_name (struct file *file);
struct exit_pair *exit_list_entry(tid_t child_tid);
block_sector_t find_prev_sector(block_sector_t sector);
bool find_dir(block_sector_t sector);
void remove_dir(block_sector_t sector);
void remove_exit_pair(struct list_elem *elem);

#endif /* userprog/syscall.h */
