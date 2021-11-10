#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "threads/thread.h"
#include <list.h>
#include <user/syscall.h>

typedef int pid_t;
struct semaphore exec_sema;
struct exit_pair{
  tid_t tid;
  int status;
  struct list_elem elem;
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

//project 3
mapid_t mmap(int fd,void *addr);
void munmap (mapid_t mapping);
//function that help syscall functions
void check_esp(void *esp);
struct file *find_file (int fd);
struct exit_pair *exit_list_entry(tid_t child_tid);
void remove_exit_pair(struct list_elem *elem);
#endif /* userprog/syscall.h */
