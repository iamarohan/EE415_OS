#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <list.h>
#include <user/syscall.h>
#include <round.h>
#include <stdbool.h>

#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/init.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/pte.h"
#include "threads/synch.h"
#include "threads/switch.h"

#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#include "devices/shutdown.h"
#include "devices/input.h"

#include "filesys/filesys.h"
#include "filesys/file.h"

#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "vm/lazy.h"

//lock to ensure syn for file system
static struct lock syscall_lock;
static void syscall_handler (struct intr_frame *);
//list where exited children's status and tid is stored
static struct list exit_list;
static bool install_page (void *upage, void *kpage, bool writable);
/* Syscall_init initialized lock, list and sends an internal interrup
with vec_no 0x30, meaning system call */
void
syscall_init (void) 
{
  sema_init (&exec_sema,1);
  lock_init (&syscall_lock);
  list_init (&exit_list);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
  //struct thread *t = thread_current();
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
      tell((int)*(uint32_t *)sys_arg[0]);
      break; 
    case SYS_CLOSE:
      close((int)*(uint32_t *)sys_arg[0]);
      break; 
    case SYS_MMAP:
      f->eax = mmap((int)*(uint32_t *)sys_arg[0],(void *)*(uint32_t *)sys_arg[1]);
      break;
    case SYS_MUNMAP:
      munmap((mapid_t)*(uint32_t *)sys_arg[0]);
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
  if (esp == NULL)
  {
    //printf("esp==NULL\n");
    exit(-1);
  }
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
  char *filename = malloc((strlen(cmd_line)+1));
  strlcpy(filename,cmd_line,strlen(cmd_line)+1);
  char *save_ptr,*token;
  for (token = strtok_r (filename, " ", &save_ptr); token != NULL;
      token = strtok_r (NULL, " ", &save_ptr));
  //printf("filename: %s\n",filename);
  struct file *file = filesys_open((char *)filename);
  if ((file == NULL) && (in_load == false))
  {
    return -1;
  }
  file_close(file);
  //printf("file test finish exec\n");

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
  check_esp((void *)file);
  if (file == NULL)
    exit(-1);
  if (strlen(file) > 14)
    return 0;
  if (strlen(file) == 0)
    return 0;
  return filesys_create (file, (uint32_t) initial_size);
}
/* Removes the file named file from the file system by calling filesys_remove */
bool
remove (const char *file)
{
  return filesys_remove (file);
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
  check_esp((void *)file);
  if (file == NULL)
    return -1;
  struct file *rtn_file;
  struct thread *t = thread_current();
  lock_acquire(&syscall_lock);
  rtn_file = filesys_open(file);
  if (strcmp(t->name,file)==0)
  { 
    file_deny_write(rtn_file);
  }
  if (NULL == rtn_file)
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
  //printf("read: %d\n",fd);
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
  void *check = (void *) buffer;
  check_esp(check);
  int result;
  struct file *file;
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
  result = file_write(file,buffer,(uint32_t)size);
  lock_release(&syscall_lock);
  return result;
}
/* Seek function doesn't do error checking.
We find the file with file descriptor fd, and sets the next point to be read
using file_seek function */
void seek (int fd, unsigned position)
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
  struct file *file;
  file = find_file(fd);
  return file_tell (file);
}
/* Close function checks if there is a file with file descriptor fd. If not, 
exit with status -1.
If else, close the file with file descriptor fd using file_close.
Using thread_close_file, we erase the fd_entry in thread t associated with
file descriptor fd. */
void 
close (int fd)
{
  struct thread *t = thread_current();
  struct file *file;
  file = find_file(fd);
  if (file == NULL)
    exit(-1);
  file_close (file);
  thread_close_file(t,fd);
}

mapid_t 
mmap(int fd,void *addr)
{
  uintptr_t round = ROUND_DOWN ((uintptr_t) addr, 4096);
  struct thread *t = thread_current();
  //printf("123: %p\n",addr);
  if ((uintptr_t)addr != round)
    return -1;
  if (find_file(fd) == NULL)
    return -1;
  if (fd == 1 || fd == 0)
    return -1;
  if (addr == NULL)
    return -1;
  if (return_paddr(t->sup_pt,addr) != NULL)
    return -1;
  int order = 0;
  struct file *file = find_file(fd);
  uint32_t read_bytes = file_length(file);
  bool writable;
  if (file_is_writable(file) == true)
    writable = 0;
  else
    writable = 1;
  while (read_bytes > 0)
  {
    
    if (return_paddr(t->sup_pt,addr) != NULL)
      return -1;
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    uint8_t *kpage = allocate_frame(false);
    //printf("vaddr:%p,paddr: %p, %d\n",addr,kpage,page_read_bytes);
    if (kpage == NULL)
      return -1;
    if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
    {
      release_frame (kpage);
      return -1; 
    }

    //printf("/////////////%d\n",strnlen(kpage,PGSIZE));
    memset (kpage + page_read_bytes, 0, page_zero_bytes);
    create_sup_pte(t->sup_pt,addr,kpage,writable);
    mapped_file (t->sup_pt, addr, fd, order, page_zero_bytes,file);
    if (!install_page (addr, kpage, writable)) 
    {
       release_frame(kpage);
       return false;
    }
    read_bytes -= page_read_bytes;
    addr += PGSIZE;
    order++;
  }
  //printf("end of line %d\n",fd);
  file_seek(file,0);
  return fd;
}

void 
munmap (mapid_t mapping)
{
  //printf("///////////////munm %d\n",mapping);

  int order = 0;
  struct thread *t = thread_current();
  void *vaddr = return_vaddr_mapped(t->sup_pt,mapping,order);
  //printf("vaddr: %p\n",vaddr);
  if (vaddr == NULL)
    return;
  void *paddr = return_paddr (t->sup_pt, vaddr);
  if (paddr == NULL)
    return;
  struct file *file = seek_file(t->sup_pt,vaddr);
  //printf("paddr: %p %s\n",paddr,(char *)paddr);
  //printf("paddr_len: %d, vaddr_len %d\n",strnlen(vaddr,PGSIZE),strnlen(paddr,PGSIZE));
 
  while (vaddr != NULL)
  {
    size_t page_write = PGSIZE;
    //printf("vaddr: %p\n",vaddr);
    paddr = return_paddr (t->sup_pt, vaddr);
    file_seek(file,0);
    //printf("tell: %d\n",file_tell(file));
    if (pagedir_is_dirty(t->pagedir,vaddr))
    {
      //printf("paddr: %s\n",(char *)vaddr);
      file_write(file,(char *)vaddr,page_write);
    }
    if (strnlen(vaddr,PGSIZE) != 0)
      release_frame(paddr);
    delete_sup_pte (t->sup_pt,vaddr);
    pagedir_clear_page (t->pagedir,vaddr);
    order++;
    vaddr = return_vaddr_mapped(t->sup_pt,mapping,order);
  }
  file_seek(file,0);
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
/* remove exit pair with list_elem inst from exit_list */
void
remove_exit_pair(struct list_elem *inst)
{
  struct exit_pair *pair = list_entry(inst,struct exit_pair, elem);
  //printf("pair: %d, %d",pair->tid,pair->status);
  list_remove(inst);
  free(pair);
}

static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
