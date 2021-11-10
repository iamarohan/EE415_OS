#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <list.h>

#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/init.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/pte.h"
#include "threads/synch.h"
#include "threads/switch.h"

#include "devices/shutdown.h"
#include "devices/input.h"

#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"

#define READDIR_MAX_LEN 14
#define MAX_DEPTH 500
//lock to ensure syn for file system
static struct lock syscall_lock;
static void syscall_handler (struct intr_frame *);
//list where exited children's status and tid is stored
static struct list exit_list;
static struct list dir_list;
static int depth;
/* Syscall_init initialized lock, list and sends an internal interrup
with vec_no 0x30, meaning system call */

void
syscall_init (void) 
{
  sema_init (&exec_sema,1);
  lock_init (&syscall_lock);
  list_init (&exit_list);
  list_init (&dir_list);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  depth = 0;
}
/* Syscall handler function takes intr_frame f as argument. Reading from stack
using *esp (stack) pointer, we parse arguments and calls the appropriate
system call.
I found out that where *esp points to is where sys_call number is stored
and arguments are stored 32-bits after that. However, I'm not entirely sure
but arguments for SYSCALL3 seems to be pushed 32*4bits after that, so I made
a special code for that. */
static void
syscall_handler (struct intr_frame *f) 
{
  //printf("%s\n","syscall_handler");
  if (f->esp == NULL)
    shutdown();
  struct thread *t = thread_current();
  void **esp = f->esp;
  check_esp(f->esp);
  void *sys_num = esp;
  int itr;
  int arg = 1;

  void **sys_arg = (void **)malloc (sizeof(void *) * 3);
  //printf("sys_num: %d, %d\n",t->tid,*(int *)sys_num);
  // if we are calling syscall_functions that use SYSCALL3
  if ((*(int *)sys_num == 8) ||(*(int *)sys_num == 9))
    arg = 5;
  //fill in arguments.
  for (itr = 0; itr < 3; itr++) // should this always be 3???
  {
    sys_arg[itr] = esp+arg+itr;
    check_esp(sys_arg[itr]);
  }
  //call the appropriate system call
  switch (*(int *) sys_num){
    case SYS_HALT:
      halt();
      break; 
    case SYS_EXIT:
      f->eax = *(int *)sys_arg[1];
      exit((int)*(uint32_t *)sys_arg[0]);
      break; 
    case SYS_EXEC:
      f->eax = exec((char *)*(uint32_t *)sys_arg[0]);
      break;
    case SYS_WAIT:
      f->eax = wait((int)*(uint32_t *)sys_arg[0]);
      break;
    case SYS_CREATE:
      f->eax = create((char *)*(uint32_t *)sys_arg[0],
        (unsigned)*(uint32_t *)sys_arg[1]);
      break; 
    case SYS_REMOVE:
      f->eax = remove((char *)*(uint32_t *)sys_arg[0]);
      break; 
    case SYS_OPEN:
      f->eax = open((char *)*(uint32_t *)sys_arg[0]);
      break; 
    case SYS_FILESIZE:
      f->eax = filesize((int)*(uint32_t *)sys_arg[0]);
      break; 
    case SYS_READ:
      f->eax = read ((int)*(uint32_t *)sys_arg[0], 
        (void *)*(uint32_t *)sys_arg[1], 
        (unsigned)*(uint32_t *) sys_arg[2]);
      break; 
    case SYS_WRITE:
      f->eax = write((int)*(uint32_t *)sys_arg[0], 
        (void *)*(uint32_t *)sys_arg[1], 
        (unsigned)*(uint32_t *)sys_arg[2]);
      break;
    case SYS_SEEK:
      seek((int)*(uint32_t *)sys_arg[0],(unsigned)*(uint32_t *)sys_arg[1]);
      break; 
    case SYS_TELL:
      f->eax = tell((int)*(uint32_t *)sys_arg[0]);
      break; 
    case SYS_CLOSE:
      close((int)*(uint32_t *)sys_arg[0]);
      break; 
    case SYS_CHDIR:
      f->eax = chdir ((const char *)*(uint32_t *) sys_arg[0]);
      break;
    case SYS_MKDIR:
      f->eax = mkdir ((const char *)*(uint32_t *) sys_arg[0]);
      break;
    case SYS_READDIR:
      f->eax = readdir ((int)*(uint32_t *) sys_arg[0], (char *)*(uint32_t *) sys_arg[1]);
      break;
    case SYS_ISDIR:
      f->eax = isdir ((int)*(uint32_t *) sys_arg[0]);
      break;
    case SYS_INUMBER: 
      f->eax  = inumber ((int)*(uint32_t *) sys_arg[0]);
      break;
    default:
      break;
  }
  free(sys_arg);
}
/* check esp checks esp checks the input pointer for three things.
1. Is esp == NULL
2. Is esp kernel vaddr
3. Is esp unmapped memory
If either of these cases are true, we call exit (-1) */
void
check_esp(void *esp)
{
  void *is_null;
  struct thread *t = thread_current();
  if (esp ==NULL)
    exit(-1);
  if (is_kernel_vaddr(esp))
  {
    exit(-1);
  }
  is_null = pagedir_get_page(t->pagedir,esp);
  if (is_null == NULL)
  {
    exit(-1);
  }
}
/* Halt function shuts down qemu or boshc. Should not be called by user */
void 
halt (void)
{
  shutdown_power_off();
}
/* Exit function prints the exist status and process name. Then calls thread
exit to terminate the process. If the terminating process is a child of a
process, it stores its pid and exit status in exit_list */
void 
exit (int status)
{
  struct thread *t = thread_current();
  char *token,*save_ptr;
  token = strtok_r (t->name, " ", &save_ptr);
  
  if (t->parent != -1)
  {
    if (thread_find(t->parent) != NULL)
    {
      struct exit_pair *ep = malloc(sizeof(struct exit_pair)*2);
      ep->tid = t->tid;
      ep->status = status;
      list_push_back(&exit_list,&ep->elem);
    }
  }
  printf("%s: exit(%d)\n",token,status);
  thread_exit();
}
/* Exec checks for two corner cases. If the user passed bad_ptr or if the 
file name referenced by cmd_line exists.
After that, it calls process_execute_child function to create a child process
Using semaphore that will only be upped after child process is loaded, it 
waits for the result of child loading comes out.
If the result returns failure, we return -1. Else, we return the child
process's tid and stores that tid in t->children tid array. */
pid_t
exec (const char *cmd_line)
{
  check_esp((void*)cmd_line);
  //check if cmd_line file does not exist
  char *filename = malloc(sizeof(char)*(strlen(cmd_line)+1));
  strlcpy(filename,cmd_line,strlen(cmd_line)+1);
  char *save_ptr,*token;
  for (token = strtok_r (filename, " ", &save_ptr); token != NULL;
      token = strtok_r (NULL, " ", &save_ptr));
  struct file *file = NULL;
  file = filesys_open(filename);
  if(file == NULL)
  {
    return -1;
  }
  file_close(file);

  //must implement synch with watit
  struct thread *t = thread_current();
  int return_val;
  //printf("call process_execute_child\n");
  return_val = process_execute_child(cmd_line,t->tid);
  //printf("%d\n",return_val);
  if (return_val == TID_ERROR)
  {
    //printf("hihierror\n");
    return -1;
  }
  else
  {
    t->child_cnt++;
    t->children = realloc(t->children,sizeof(tid_t)*t->child_cnt+1);
    t->children[t->child_cnt] = return_val;
    return return_val;
  }
}
/* Calls process_wait and returns the resulting value. Further explanation will 
be done in process_wait function. */
int 
wait (pid_t pid)
{
  int return_val;
  return_val = process_wait(pid);
  //printf("%d\n",return_val);
  return return_val;
}

/* Creates a file named file with size initial_size by calling the filesys_create
function. It checks if the passed pointer is a bad_ptr, and if the file name 
is NULL. */
bool 
create (const char *file, unsigned initial_size)
{
  //printf("create file: %s\n",file);
  check_esp((void *)file);
  if (file == NULL)
    exit(-1);
  if (strlen(file) > 14)
    return false;
  if (strlen(file) == 0)
    return false;
  struct thread *t = thread_current();
  char *dir_name = malloc(sizeof(char)*(strlen(file)+1));
  strlcpy(dir_name,file,strlen(file)+1);
  struct dir *wk_dir = point_to_dir (dir_name, t->wk_sector);
  if (wk_dir == NULL)
    return false;
  //printf("create file: %s\n",dir_name);
  bool check = filesys_create_sub (dir_name,initial_size, wk_dir);

  //printf("check: %d\n",wk_dir->inode->sector);
  dir_close(wk_dir);
  //shutdown();
 // printf("end create\n");
 
  return check;
}
/* Removes the file named file from the file system by calling filesys_remove */
bool
remove (const char *file)
{
  //printf("remove: %s\n",file);
  char *dir_name = malloc(sizeof(char)*(strlen(file)+1));
  strlcpy(dir_name,file,strlen(file)+1);
  struct thread *t = thread_current();
  struct dir *wk_dir = point_to_dir(dir_name,t->wk_sector);
  if (wk_dir == NULL)
    return false;
  struct file *ck_file = filesys_open_sub(dir_name,wk_dir);
  //printf("file_sector: %d\n",ck_file->inode->sector);
  //printf("%d\n",wk_dir->inode->sector);
  //printf("%s\n",dir_name);

  if (strcmp("..",dir_name) == 0)
  {
    file_close(ck_file);
    return false;
  }
  if (strcmp(".",dir_name) == 0)
  {
    file_close(ck_file);
    return false;
  }
  if (ck_file == NULL)
  {
    file_close(ck_file);
    return false;
  }
  if (ck_file->inode->sector == t->wk_sector)
  {
    file_close(ck_file);
    return false;
  }
  if (!find_dir(ck_file->inode->sector))
  {
    struct file *file = find_file_name (ck_file);
    if (file != NULL)
    {
      file_close(ck_file);
      return false;
    }
    if (dir_num(dir_open(ck_file->inode)) != 0)
    {
      file_close(ck_file);
      return false;
    }
    remove_dir(ck_file->inode->sector);
    //printf("here\n");
  }
  
  //printf("end of remove\n");
  //dir_close(wk_dir);
  int result = filesys_remove_sub(dir_name,wk_dir);
  free(dir_name);
  file_close(ck_file);
  
  return result;
}

/* open system call opens a file named file. 
It chekcs for three cases. If the passed pointer is bad_ptr, if the passed
pointer is NULL and if there is no file named file.
To ensure synchronization, we acquire the lock at the start of the function
and release right before the function returns. 
I open the file using filesys_open function and denies the write if the file
is an executable.
I create a file descriptor for the file and stores a fd_entry of the file
in the process's thread. 
After that, I return the file's fd. */
int
open (const char *file)
{
  //printf("open: %s",file);
  check_esp((void *)file);
  if (file == NULL)
    return -1;
  struct file *rtn_file;
  struct thread *t = thread_current();
  if (strlen(file) == 0)
    return -1;
  lock_acquire(&syscall_lock);
  
  char *dir_name = malloc(sizeof(char)*(strlen(file)+1));
  strlcpy(dir_name,file,strlen(file)+1);

  struct dir *wk_dir = point_to_dir(dir_name,t->wk_sector);
  if (wk_dir == NULL)
  {
    lock_release(&syscall_lock);
    return -1;
  }
  //printf("open: %s\n",dir_name);
  rtn_file =filesys_open_sub(dir_name,wk_dir);
  //printf("open: %d\n",rtn_file->inode->sector);
  if (strcmp(t->name,file)==0)
    file_deny_write(rtn_file);
  if (rtn_file == NULL)
  {
    lock_release(&syscall_lock);
    return -1;
  }
  struct fd_entry *new_file = malloc(sizeof(struct fd_entry *));
  new_file->fd = t->fd_cnt;
  new_file->file = rtn_file;
  t->fd_cnt++;
  char *tmp = malloc(sizeof(char) * (strlen(file)+1));
  new_file->name = tmp;
  strlcpy(new_file->name,file,strlen(file)+1);
  new_file->next = NULL;
  thread_add_file(t,new_file);
  lock_release(&syscall_lock);
  //printf(" %d\n",t->fd_cnt-1);
  return (t->fd_cnt - 1);
  
}
/* Filesize function first checks if the file referenecd by fd actually exists.
After that, I return the size of the file referenced by fd using file_lentgth
function */
int 
filesize (int fd)
{
  struct file *file;
  file = find_file(fd);
  if (file == NULL)
    exit(-1);
  return file_length(file);
}
/* Read funcition checks for two cases. If buffer pointer is bad_ptr, if
there is no open file with file descriptor fd.
We then acquire syscall_lock, which is released right before the function
retunrs or calls exit.
If fd == 0, we read allocate memory to a buffer. Then we read from console 
using input_getc function. We read until we've read size number of bytes 
or until line end.
If file is already poinitng to the end of file, or if size is 0, we read 
nothing and return 0.
If else, we read the file using fil_read function. If there was an error, 
return -1. If not, return the number of bytes read. */
int 
read (int fd, void *buffer, unsigned size)
{
  check_esp(buffer);
  struct file *file;
  unsigned bytes_read = 0;
  char *ch_buffer;
  if (fd == 0) 
  {
    ch_buffer = malloc(sizeof(char) * size);
  }
  char c;
  lock_acquire(&syscall_lock);
  if (fd ==0)
  {
    while(1)
    {
      c = input_getc();
      if ((c == '\0') || (bytes_read>size))
        break;
      ch_buffer[bytes_read] = c;
      bytes_read++;
    }
    strlcpy((char *)buffer,ch_buffer,bytes_read);
    lock_release(&syscall_lock);
    return bytes_read;
  }
  file = find_file(fd);
  if (file == NULL)
  {
    lock_release(&syscall_lock);
    exit(-1);
  }
  //if end of file
  if (file_tell(file) == file_length(file))
  {
    lock_release(&syscall_lock);
    return 0;
  }
  if (size == 0)
  {
    lock_release(&syscall_lock);
    return 0;
  }
  bytes_read = file_read (file, buffer, (uint32_t) size);
  lock_release(&syscall_lock);
  if ((bytes_read == 0))
    return -1;
  else
    return bytes_read;
}
/* Write funcition checks for two cases. If buffer pointer is bad_ptr, if
there is no open file with file descriptor fd.
We then acquire syscall_lock, which is released right before the function
retunrs or calls exit.
If fd == 1, we read from console using putbuf function. 
If else, we read the file for size bytes using file_write function.
We return the amount of bytes read. */
int
write (int fd, const void *buffer,unsigned size)
{
  //printf("write: %d, %d\n",fd,size);
  void *check = (void *) buffer;
  check_esp(check);
  int result;
  struct file *file;
  struct thread *t;
  lock_acquire(&syscall_lock);
  if (fd == 1)
  {
    putbuf(buffer,size);
    lock_release(&syscall_lock);
    return size;
  }
  file = find_file(fd);
  if (file == NULL)
  {
    lock_release(&syscall_lock);
    exit(-1);
  }
  if (!find_dir(file->inode->sector))
  {
    lock_release(&syscall_lock);
    return -1;
  }
  result = file_write(file,buffer,(uint32_t)size);
  //file->pos += result;
  //printf("pos after write: %d\n",file->pos);
  lock_release(&syscall_lock);
  //printf("write_result: %d\n",result);
  return result;
}
/* Seek function doesn't do error checking.
We find the file with file descriptor fd, and sets the next point to be read
using file_seek function */
void 
seek (int fd, unsigned position)
{
  struct file *file;
  file = find_file(fd);
  file_seek (file, (uint32_t) position);
}
/* tell function finds file with file descriptor fd and returns position of the
next byte to be read using file_tell function */
unsigned 
tell (int fd)
{
  //printf("tell: %d\n",fd);
  struct file *file;
  file = find_file(fd);
  //printf("length: %d\n",(unsigned)file->pos);
  long answer = file->pos;
  //printf("answer: %d\n",answer);
  return answer;
}
/* Close function checks if there is a file with file descriptor fd. If not, 
exit with status -1.
If else, close the file with file descriptor fd using file_close.
Using thread_close_file, we erase the fd_entry in thread t associated with
file descriptor fd. */
void 
close (int fd)
{
  //printf("close: %d\n",fd);
  struct thread *t = thread_current();
  struct file *file;
  file = find_file(fd);
  //printf("close: %d\n",file->inode->sector);
  if (file == NULL)
  {
    //printf("close_wrong\n");
    exit(-1);
  }
  file_close (file);
  thread_close_file(t,fd);
}
bool
chdir (const char *dir)
{
  struct thread *t = thread_current();
  if (strcmp(dir,"/") == 0)
  {
    t->wk_sector = ROOT_DIR_SECTOR;
    return true;
  }
  //printf("start chdir: %d\n",t->wk_sector);
  char *dir_name = malloc(sizeof(char)*(strlen(dir)+1));
  strlcpy(dir_name,dir,strlen(dir)+1);
  //printf("middle chdir:");
  struct dir *wk_dir = point_to_dir(dir_name,t->wk_sector);
  //printf("prev chdir: %d\n",wk_dir->prev_sector);
  //printf("how bad: %d\n",wk_dir->inode->open_cnt);
  struct inode *inode = NULL;
  if (strcmp(dir_name,"..") != 0)
  {
    if (!dir_lookup(wk_dir,dir_name,&inode))
    {
      //printf("errorfinder\n");
      return false;
    }
    struct dir *new_dir = dir_open(inode);
    t->wk_sector = new_dir->inode->sector;
    dir_close(new_dir);
  }
  else
  {
    t->wk_sector = wk_dir->inode->sector;
  }
  //printf("%d\n",t->wk_sector);
  //shutdown();
  //printf("end chdir: %d\n",t->wk_sector);
  
  dir_close(wk_dir);
  //free(dir_name);
  depth++;
  return true;
}

bool 
mkdir (const char *dir)
{
  if (dir == NULL)
    return false;
  if (strlen(dir) == 0)
    return false;
  if (depth >= MAX_DEPTH)
    return false;
  struct thread *t = thread_current();
  block_sector_t dir_sector;
  char *dir_name = malloc(sizeof(char)*(strlen(dir)+1));
  strlcpy(dir_name,dir,strlen(dir)+1);

  struct dir *wk_dir = point_to_dir(dir_name,t->wk_sector);

  //shutdown();
  free_map_allocate(1,&dir_sector);
  //t->prev_sector = t->wk_sector;
  //wk_dir->prev_sector = t->prev_sector;
  if (!dir_create (dir_sector, 16))
  {
    //printf("end1\n");
    free_map_release(dir_sector,1);
    dir_close(wk_dir);
    free(dir_name);
    return false;
  }
  //printf("dirsector: %d\n",dir_sector);
  if (!dir_add (wk_dir,dir_name,dir_sector))
  {
    //printf("end2\n");
    free_map_release(dir_sector,1);
    dir_close(wk_dir);
    free(dir_name);
    return false;
  }

  struct dir_sector *de = malloc(sizeof(struct dir_sector)+1);
  de->sector = dir_sector;
  de->prev_sector = t->wk_sector;
  list_push_back(&dir_list,&de->elem);

  dir_close(wk_dir);
  //printf("mkdir_1: %d\n", dir_sector);
  //shutdown();
  free(dir_name);
  return true;
}

bool 
readdir (int fd, char name[READDIR_MAX_LEN + 1])
{
  //printf("readdir: %d, %d\n",fd, strlen(name));
  struct file *file = find_file(fd);
  struct dir *dir = dir_open(file->inode);
  dir->pos = file->pos;
  //printf("how bad: %d\n",dir->inode->open_cnt);
  if (!dir_readdir(dir,name))
  {
    dir_close(dir);
    file->pos += 20;
    return false;
  }
  //printf("%s\n",name);
  dir_close(dir);
  file->pos += 20;
  return true;
}

bool
isdir (int fd)
{
  struct file *file = find_file(fd);
  if (!find_dir(file->inode->sector))
    return true;
  return false;
}

int 
inumber (int fd)
{
  struct file *file = find_file(fd);
  int inumber = file->inode->sector;
  //file_close(file);
  return inumber;
}

/* finds a file associated with file descriptor fd */
struct file*
find_file (int fd)
{
  struct thread *t = thread_current();
  struct fd_entry *file_entry = t->proc_file;
  int flag = 0;
  if (file_entry == NULL)
    return NULL;
  for (;file_entry->next != NULL;file_entry = file_entry->next)
  {
    if (file_entry->fd == fd)
    {
      flag = 1;
      break;
    }
  }
  if (flag == 0)
  {
    if (file_entry->fd != fd)
    {
      return NULL;
    }
  }
  return file_entry->file;
}

struct file*
find_file_name (struct file *file)
{
  struct thread *t = thread_current();
  struct fd_entry *file_entry = t->proc_file;
  int flag = 0;
  if (file_entry == NULL)
    return NULL;
  for (;file_entry->next != NULL;file_entry = file_entry->next)
  {
    if (memcmp(file_entry->file,file,sizeof(file)) == 0)
    {
      flag = 1;
      break;
    }
  }
  if (flag == 0)
  {
    if (memcmp(file_entry->file,file,sizeof(file)) != 0)
    {
      return NULL;
    }
  }
  return file_entry->file;
}

/* return a exit_pair structure that has tid equal to child_tid */
struct exit_pair*
exit_list_entry(tid_t child_tid)
{
  struct list_elem *init;
  struct exit_pair *itr;
  if (list_size(&exit_list) == 0)
    return NULL;
  for(init = list_front(&exit_list);init->next != NULL;init = init->next)
    {
      itr = list_entry (init, struct exit_pair, elem);
      //printf("exit_list: %d\n",itr->tid);
      if (itr->tid == child_tid)
      {
        return itr;
      }
    }
  return NULL;
}

block_sector_t
find_prev_sector(block_sector_t sector)
{
  struct list_elem *init;
  struct dir_sector *itr;
  if (list_size(&dir_list) == 0)
    return 0;
  for(init = list_front(&dir_list);init->next != NULL;init = init->next)
    {
      itr = list_entry (init, struct dir_sector, elem);
      if (itr->sector == sector)
      {
        return itr->prev_sector;
      }
    }
  return 0;
}

bool
find_dir(block_sector_t sector)
{
  struct list_elem *init;
  struct dir_sector *itr;
  if (list_size(&dir_list) == 0)
    return true;
  for(init = list_front(&dir_list);init->next != NULL;init = init->next)
    {
      itr = list_entry (init, struct dir_sector, elem);
      if (itr->sector == sector)
      {
        return false;
      }
    }
  return true;
}

void
remove_dir(block_sector_t sector)
{
  struct list_elem *init;
  struct dir_sector *itr;
  if (list_size(&dir_list) == 0)
    return;
  for(init = list_front(&dir_list);init->next != NULL;init = init->next)
    {
      itr = list_entry (init, struct dir_sector, elem);
      if (itr->sector == sector)
      {
        list_remove(init);
        free(itr);
        return;
      }
    }
  return;
}


/* remove exit pair with list_elem inst from exit_list */
void
remove_exit_pair(struct list_elem *inst)
{
  struct exit_pair *pair = list_entry(inst,struct exit_pair, elem);
  //printf("pair: %d, %d",pair->tid,pair->status);
  list_remove(inst);
  free(pair);
}
