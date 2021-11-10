#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <list.h>

struct wait_list{
	tid_t tid;
	struct list_elem elem;
};

tid_t process_execute (const char *file_name);
tid_t process_execute_child (const char *file_name, tid_t parent_tid);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void init_wait_list (void);

#endif /* userprog/process.h */
