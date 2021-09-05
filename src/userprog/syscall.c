#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
void syscall_error_exit(void);
uint32_t is_memory_avail_to_read(void *);
struct file_elem * find_file_by_fn(off_t fn);
struct file_elem * find_file_by_name(char* file_name);
bool set_remove_file_by_name(char* file_name);
bool is_this_file_removed(char* file_name);//1이면 remove
bool is_this_ben(char * file_name);

//int write_memory(onst uint8_t * uaddr, uint8_t byte);

uint32_t file_num;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  //rindid modi
  file_num=1;
  
  file_open_sema=(struct semaphore *)malloc(sizeof(struct semaphore));
  sema_init(file_open_sema, 1);
  file_creat_sema=(struct semaphore *)malloc(sizeof(struct semaphore));
  sema_init(file_creat_sema, 1);
//  file_remove_sema=(struct semaphore *)malloc(sizeof(struct semaphore));
//  sema_init(file_remove_sema, 0);
  file_write_sema=(struct semaphore *)malloc(sizeof(struct semaphore));
  sema_init(file_write_sema, 1);

  list_init(&file_list);
  list_init(&write_ben_list);
  to_debug=0;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  unsigned ui;
  tid_t tid;
  void * buffer;
  int i, a, b;
  struct file * s_file;
  struct file_elem * s_file_elem;
  struct list_elem * tmp_e;

  if(debug_flag) printf ("system call!\n");
  if(debug_flag) printf(">>> 11 error_code:%d\n",f->error_code);
  if(debug_flag) printf(">>> 22 esp_pointer:%p\n",f->esp);

  //memory error 
  if(is_memory_avail_to_read((f->esp))==false)
  {
	if(debug_flag) printf(" >>> this is f->esp error!!\n");
	//f->eax=-1;
	//f->error_code=-1;
	thread_current()->i_am_child->child_error_code = -1;
	thread_exit();
	//exit(-1);
	//printf("%s: exit(-1)\n", *(char**)(f->esp+4));
	//syscall_error_exit();
	return;
  }
  if(debug_flag) printf(">>> [User-sysnum:%d]\n",*(uint32_t*)(f->esp));
//if(debug_flag) printf(">>> argument1 Name : [%s]\n", *(char**)(f->esp+4));
//  hex_dump((uintptr_t)(f->esp),(f->esp), 300, true);
// to do : memory 범위를 벗어난 것들 에러
  if(debug_flag) printf(">>> 1111\n");
  switch(*(uint32_t *)(f->esp))
  {
	case SYS_HALT:
	{
		if(debug_flag) printf(">>> i am halt\n");
		shutdown_power_off();
		break;
	}
	case SYS_EXIT:
	{
		if(is_memory_avail_to_read((int*)(f->esp+4))==false){syscall_error_exit();return;}
		if(debug_flag) printf(">>> child_error_code:%d\n",*(int*)(f->esp+4));
		thread_current()->i_am_child->child_error_code=*(int*)(f->esp+4);
		thread_exit ();
		/* 자식 입장 */
		// V 요절할 수 있다.
		// V 내 i_am_child에 써줘야 한다.
		/* 부모입장 */
		//아래에 있는 child의 고려가 필요. 자식들이 죽기전에는 죽지못함.
		//그 전까지는 wait해야함.
		break;
	}
	case SYS_EXEC:
	{
		if(is_memory_avail_to_read(*(char**)(f->esp+4))==false){syscall_error_exit();return;}
		if(debug_flag) printf(">> SYS_EXEC and prev excuted %s\n", *(char**)(f->esp+4));
		sema_down(file_write_sema);
		tid=process_execute(*(char**)(f->esp+4));
		sema_up(file_write_sema);
		//if(tid==-1) printf("%s: exit(-1)\n", *(char**)(f->esp+4)); 
		/* process_execute 내부에서 해 주어야 할 일.
		V * thread 생성시에(?) child를 만들고 이를 부모의 child의 리스트에 저장할 필요가 있다.
		V * 끝나고 난 exec의 상태를 어딘가에다가 저장해주어야. 아마 그것이 child에 저장.
		V * sema parent up - parent가 잘 돌아가도록 하기 위해 필요.
		V * sema는 올려줌으로써 parent가 돌아감. 허나 exec하고 그것이 끝난 상태를 보낼 필요가 있다.*/
	//	if(debug_flag) printf(">> sema_down to make thread :[%u]\n",&(thread_current()->i_am_making_thread));
	//	sema_down(&(thread_current()->i_am_making_thread));
		//sema now down - child가 올려주기 전까지는 뒤진다.
		f->eax=tid;
		//과연 child는 잘 끝났나? 이걸 어케 확인해야하나.

		break;
	}
	case SYS_WAIT:
	{
		if(is_memory_avail_to_read((tid_t*)(f->esp+4))==false){syscall_error_exit();return;}
		if(debug_flag) printf(">> SYS_WAIT CALLED\n");
		f->eax=process_wait(*(tid_t*)(f->esp+4));
		//1. 인자로 받은 pid가 내 자식인지 확인한다
		//2. 자식이 맞다면, 그 자식이 죽었는지 확인한다. 죽지 않았다면 기다린다.
		//3. 이 기다리는 과정은 sema로 만들 수 있다.
		//내가 짠 sudo코드에서는 process_execute는 무조건 sema를 들어갔다 나오도록 지정되어 있다. 허나 아닐 경우가 있을...까? 아니면 이미 죽은 애들을 wait할 수도 있다. 이러한 경우 wait을 위해 일단 child가 죽어도 그 저장된 배열의 경우 free되지 않아야 한다. 또한 wait는 한번만 call한다고 한다. 이점 유의.
		break;
	}
	case SYS_READ://int read(int fd, void *buffer, unsigned size)//esp+4, esp+8, esp+12
	{//fd의 파일을 size만큼 읽어 이를 buffer에 저장한다. 이때 리턴은 actually 읽은 숫자이다.
		if(is_memory_avail_to_read((int*)(f->esp+4))==false){syscall_error_exit();return;}
		if(is_memory_avail_to_read(*(void **)(f->esp+8))==false){syscall_error_exit();return;}
		if(is_memory_avail_to_read((unsigned*)(f->esp+12))==false){syscall_error_exit();return;}
		buffer = *(void **)(f->esp+8);
		if(debug_flag2) printf("[[SYSCALL READ!!]]\n");
		if(*(int*)(f->esp+4)==0)//stdin
		{ 
			for(ui=0; ui<*(unsigned*)(f->esp+12);ui++)
			{
				*(uint8_t *)(buffer+ui)=input_getc();
				if(*(uint8_t *)(buffer+ui)==0) break;
			}
			f->eax=ui;
		}
		else if(*(int*)(f->esp+4)>=2)//file
		{
			if(debug_flag2) printf("[[check1111]]\n");
		//read가 동시에 수행될 경우? -> 같이?
			s_file_elem=find_file_by_fn(*(int*)(f->esp+4));
			if(s_file_elem!=NULL)
			{
				if(s_file_elem->my_thread_tid != thread_current()->tid) { f->eax=-1; break; }
				file_deny_write(s_file_elem->fd);
				if(debug_flag2) printf("[[file is reading...]]\n");
				f->eax=file_read(s_file_elem->fd, buffer, *(off_t*)(f->esp+12));
			//	file_allow_write(s_file_elem->fd);
				if(debug_flag2) printf("[[file read end...]]\n");
			}
			else if(debug_flag2) printf("[[file read:no file]]\n");
		}
		break;
	}
	case SYS_WRITE://int write(int fd, const void *buffer, unsigned size)
	{
		if(is_memory_avail_to_read((int*)(f->esp+4))==false){syscall_error_exit();return;}
		if(is_memory_avail_to_read(*(char **)(f->esp+8))==false){syscall_error_exit();return;}
		if(is_memory_avail_to_read((size_t*)(f->esp+12))==false){syscall_error_exit();return;}
		//to do:write execption
		buffer = *(void **)(f->esp+8);
		if(debug_flag) printf(">>> arg=%d\n",*(int*)(f->esp+12));
		if(*(int*)(f->esp+4)==1)//stdout
		{
			if(debug_flag2) printf("[[0 : stdout - writing...]]\n");
			putbuf(*(char **)(f->esp+8), *(size_t*)(f->esp+12));//putbuf (const char *buffer, size_t n)
			f->eax=*(size_t*)(f->esp+12);
		//	hex_dump((uintptr_t)(f->esp),(f->esp), 500, true);
		}
		else if(*(int*)(f->esp+4)>=2)//file
		{
			if(debug_flag2) printf("[[1 : file is writing...]]\n");
			s_file_elem=find_file_by_fn(*(int*)(f->esp+4));
			if(s_file_elem!=NULL)
			{
				if(s_file_elem->my_thread_tid != thread_current()->tid) { f->eax=-1; break; }
				if(debug_flag2) printf("[[2 : file is writing...]]\n");
				if(is_this_ben(s_file_elem->file_name))
				{
					if(debug_flag2) printf("[[write ben because file is exe...]]\n");
					f->eax=0; 
					break;
				}
				if(*(off_t*)(f->esp+12)==0)
				{
					if(debug_flag2) printf("[[file write size is zero]]\n");
					f->eax=0;
					break;
				}
				sema_down(file_write_sema);
				f->eax=file_write(s_file_elem->fd, buffer,  *(off_t*)(f->esp+12));
				sema_up(file_write_sema);
				if(debug_flag2) printf("[[file write end <f->eax=%d>]]\n",f->eax);
				/*while(1)
				{
					sema_down(file_write_sema);
					f->eax=file_write(s_file_elem->fd, buffer,  *(off_t*)(f->esp+12));
					sema_up(file_write_sema);
					if(f->eax !=0) break;
				}*/
			}
			else if(debug_flag2) printf("[[file write:no file]]\n");
		}
		break;
	}
	case SYS_PIBO:
	{
		if(is_memory_avail_to_read((int*)(f->esp+4))==false){syscall_error_exit();return;}
		a=0; b=1;
		for(i=1; i<*(int*)(f->esp+4); i++)
		{
			b=a+b;
			a=b-a;
		}
		if(*(int*)(f->esp+4)==0) f->eax=0;
		else if(*(int*)(f->esp+4)==1) f->eax=1;
		else f->eax=b;
		break;
	}
	case SYS_SUM:
	{
		if(is_memory_avail_to_read((int*)(f->esp+4))==false){syscall_error_exit();return;}
		if(is_memory_avail_to_read((int*)(f->esp+8))==false){syscall_error_exit();return;}
		if(is_memory_avail_to_read((int*)(f->esp+12))==false){syscall_error_exit();return;}
		if(is_memory_avail_to_read((int*)(f->esp+16))==false){syscall_error_exit();return;}
		f->eax=*(int*)(f->esp+4)+=*(int*)(f->esp+8)+=*(int*)(f->esp+12)+=*(int*)(f->esp+16);
		break;
	}
	//USER PROG 2 SYSCALL
	//where is critical section?
	case SYS_CREATE:
	{
		if(is_memory_avail_to_read(*(char **)(f->esp+4))==false){syscall_error_exit();return;}
		if(is_memory_avail_to_read((off_t*)(f->esp+8))==false){syscall_error_exit();return;}
		sema_down(file_creat_sema);	
		f->eax=filesys_create(*(char **)(f->esp+4), *(off_t*)(f->esp+8));
		sema_up(file_creat_sema);
		break;
	}
	case SYS_REMOVE:
	{
		if(is_memory_avail_to_read(*(char **)(f->esp+4))==false){syscall_error_exit();return;}
		//file이 open된 것이 없을 때 
		//강제로 shutdown으로 들어간다면?
		if(is_this_ben(*(char **)(f->esp+4)))
		{
		    if(debug_flag2) printf("[[remove ben because file is exe...]]\n");
		    f->eax=0;
		    break;
		}
		if(find_file_by_name(*(char **)(f->esp+4))==NULL)
		{
			if(debug_flag2) printf("[[REMOVED in REMOVE]]\n");
			sema_down(file_creat_sema);
			f->eax=filesys_remove(*(char **)(f->esp+4));
			sema_up(file_creat_sema);
		}
		else //remove flag
			f->eax=set_remove_file_by_name(*(char **)(f->esp+4));
		break;
	}
	case SYS_OPEN:
	{
		/* 일단 각 thread마다 fd가 존재한다. return은 f->eax가 아닌 이 thread의 fd로 들어간다. */
		/* cs가 어디인가? -> filesys_open(), 왜냐면 dir은 겹침.*/
		/* OPEN과 CLOSE사이에 SYNCH문제는 생기지 않는가?*/
		//printf("open-b:<<%p>> | e:<<%p>>\n",list_begin(&file_list),list_end(&file_list));
		if(is_memory_avail_to_read(*(char **)(f->esp+4))==false){syscall_error_exit();return;}
		sema_down(file_open_sema);
		s_file=filesys_open(*(char **)(f->esp+4));
		if(s_file==NULL)//실패
			f->eax=-1;
		else if(is_this_file_removed(*(char **)(f->esp+4)))//삭제될 예정
			f->eax=-1;
		else
		{
			s_file_elem=(struct file_elem*)malloc(sizeof(struct file_elem));
			s_file_elem->fd=s_file;
			s_file_elem->fd_num=(++file_num);
			strlcpy(s_file_elem->file_name, *(char **)(f->esp+4),strlen(*(char **)(f->esp+4))+1);
			s_file_elem->remove_flag=0;
			s_file_elem->my_thread_tid=thread_current()->tid;
			//printf("[[%s]]\n",s_file_elem->file_name);
			//s_file_elem->is_closed=0;
			//thread_current()->file_pointer=s_file_elem;
			list_push_front(&file_list, &(s_file_elem->elem));
//printf("open-b:<<%p>>|<<%p>>|e:<<%p>>\n",list_begin(&file_list),&(s_file_elem->elem), list_end(&file_list));
			f->eax=file_num;
		}
		sema_up(file_open_sema);
		break;
	}
	
	case SYS_CLOSE:
	{
		if(debug_flag2) printf("[[file close in...]]\n");
		if(is_memory_avail_to_read((int*)(f->esp+4))==false){syscall_error_exit();return;}
		
		s_file_elem=find_file_by_fn(*(int*)(f->esp+4));
		if(s_file_elem!=NULL && s_file_elem->my_thread_tid != thread_current()->tid) { f->eax=-1; break; }
		/*
		if(s_file_elem->remove_flag==1)
		{
			if(debug_flag2) printf("[[REMOVED in CLOSE]]\n");
			sema_down(file_creat_sema);
			filesys_remove(*(char **)(f->esp+4));// 잘 됐는지 확인 ㄴㄴ
			sema_up(file_creat_sema);
		}*/
		sema_down(file_open_sema);
		for(tmp_e=list_begin(&file_list); tmp_e !=list_end(&file_list); tmp_e=list_next(tmp_e))
		{
			s_file_elem=list_entry(tmp_e, struct file_elem, elem);
			if(s_file_elem->fd_num==*(int *)(f->esp+4))
			{
				file_close(s_file_elem->fd);
				if(s_file_elem->remove_flag==1)
				{
					if(debug_flag2) printf("[[REMOVED in CLOSE]]\n");
					sema_down(file_creat_sema);
					filesys_remove(s_file_elem->file_name);// 잘 됐는지 확인 ㄴㄴ
					sema_up(file_creat_sema);
				}
				list_remove(tmp_e);
				free(s_file_elem);
				if(debug_flag2) printf("[[file closed]]\n");
				break;
			}
		}
		sema_up(file_open_sema);
		if(debug_flag2 && tmp_e==list_end(&file_list)) printf("[[file close:no file]]\n");
		break;
	}
	case SYS_FILESIZE:
	{
		if(is_memory_avail_to_read((int*)(f->esp+4))==false){syscall_error_exit();return;}
		s_file_elem=find_file_by_fn(*(int*)(f->esp+4));
		if(s_file_elem!=NULL) f->eax=file_length(s_file_elem->fd);
		else if(debug_flag2) printf("[[filesize:no file]]\n");
		break;
	}
	case SYS_SEEK:
	{
		if(is_memory_avail_to_read((int*)(f->esp+4))==false){syscall_error_exit();return;}
		if(is_memory_avail_to_read((unsigned*)(f->esp+8))==false){syscall_error_exit();return;}
		s_file_elem=find_file_by_fn(*(int*)(f->esp+4));
		file_allow_write(s_file_elem->fd);
		if(s_file_elem!=NULL)
			file_seek(s_file_elem->fd, *(off_t*)(f->esp+8));
		else if(debug_flag2) printf("[[file seek:no file]]\n");
		break;
	}
	case SYS_TELL:
	{
		if(is_memory_avail_to_read((int*)(f->esp+4))==false){syscall_error_exit();return;}
		s_file_elem=find_file_by_fn(*(int*)(f->esp+4));
		if(s_file_elem!=NULL) f->eax=file_tell(s_file_elem->fd);
		break;
	}

	if(debug_flag) printf(">>> this is not valid syscall\n");
	//f->eax=-1;
	syscall_error_exit();
  }
//  thread_exit ();
}
void syscall_error_exit()
{
	if(debug_flag) printf(">>> here is memory error");
	thread_current()->i_am_child->child_error_code = -1;
	thread_exit();
//	exit(-1);
//	struct thread *cur = thread_current ();
//	printf("%s: exit(-1)\n", *(char**)(f->esp+4));
}
uint32_t is_memory_avail_to_read(void * uaddr)
{
	struct thread *t = thread_current ();
//	int result=0;
	if(debug_flag) printf(">>> is_this_memory_avail_to_read?\n");
	if(!is_user_vaddr(uaddr)) return false;
	if(pagedir_get_page(t->pagedir, uaddr)==NULL) return false;
	//if( (void *)uaddr >= PHYS_BASE ) return false;
	//asm volatile("movl $1f, %0; movzbl %1, %0; 1:": "=&a" (result) : "m" (*(uint8_t *)uaddr));
	//if(result ==-1) return false;
	if(debug_flag) printf(">>> memory_avail_to_read\n");
	return true;
}
/*
int write_memory(onst uint8_t * uaddr, uint8_t byte)
{
	int error_code;
	if( (void *)uaddr < PHYS_BASE ) return false;
	asm ("movl $1f, %0; movb %b2, %1; 1:": "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code!=-1;
}*/
struct file_elem * find_file_by_fn(off_t fn)
{
	struct list_elem * tmp_e;
	struct file_elem * s_file_elem;
	for(tmp_e=list_begin(&file_list); tmp_e !=list_end(&file_list); tmp_e=list_next(tmp_e))
	{
		s_file_elem=list_entry(tmp_e, struct file_elem, elem);
		if(s_file_elem->fd_num==fn)
			return s_file_elem;
	}
	return NULL;
}

struct file_elem * find_file_by_name(char* file_name)
{
    struct list_elem * tmp_e;
    struct file_elem * s_file_elem;
    for(tmp_e=list_begin(&file_list); tmp_e !=list_end(&file_list); tmp_e=list_next(tmp_e))
    {
        s_file_elem=list_entry(tmp_e, struct file_elem, elem);
        if(strcmp(s_file_elem->file_name,file_name)==0)
            return s_file_elem;
    }
    return NULL;
}

bool set_remove_file_by_name(char* file_name)//이미 set되어 있으면 false
{
    struct list_elem * tmp_e;
    struct file_elem * s_file_elem;
	//if(debug_flag2) printf("[[find file name <%s>]]\n", file_name);
    for(tmp_e=list_begin(&file_list); tmp_e !=list_end(&file_list); tmp_e=list_next(tmp_e))
    {
        s_file_elem=list_entry(tmp_e, struct file_elem, elem);
        if(strcmp(s_file_elem->file_name,file_name)==0)
		{
			if(s_file_elem->remove_flag==0) s_file_elem->remove_flag=1;
			else return false;
		}
    }
	return true;
}

bool is_this_file_removed(char* file_name)//1이면 remove
{
    struct list_elem * tmp_e;
    struct file_elem * s_file_elem;
    //if(debug_flag2) printf("[[find file name <%s>]]\n", file_name);
    for(tmp_e=list_begin(&file_list); tmp_e !=list_end(&file_list); tmp_e=list_next(tmp_e))
    {
        s_file_elem=list_entry(tmp_e, struct file_elem, elem);
        if(strcmp(s_file_elem->file_name,file_name)==0)
            if(s_file_elem->remove_flag==1) return true;
    }
	return false;
}

bool is_this_ben(char * file_name)
{
	struct list_elem * tmp_e;
	struct write_ben_elem * ben_e;
	if(file_name==NULL) return false;
	for(tmp_e=list_begin(&write_ben_list); tmp_e !=list_end(&write_ben_list); tmp_e=list_next(tmp_e))
	{
		ben_e=list_entry(tmp_e, struct write_ben_elem, elem);
		if(debug_flag2) printf("[[cmp : <list:%s> and <%s>]]\n",ben_e->file_name, file_name);
		if(strcmp(ben_e->file_name, file_name)==0) return true;
	}
	return false;
}
