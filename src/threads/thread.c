#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#include "devices/timer.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */
static unsigned thread_ticks22;
#ifndef USERPROG
bool thread_prior_aging;
#endif
/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

unsigned long long aaa, bbb;
/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
	int i;
	ASSERT (intr_get_level () == INTR_OFF);
  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&block_list);
  list_init (&all_list);
  for(i=0;i<70;i++)
	  pri_array[i]=-100;
  load_avg=0;
  thread_ticks22=0;
  aaa=((unsigned long long)59<<28)/((unsigned long long)60<<14);
  bbb=((unsigned long long)1<<28)/((unsigned long long)60<<14);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
//rindid_modi
  //sema_now=(struct semaphore*)malloc(sizeof(struct semaphore));
  (initial_thread->i_am_child)->tid=initial_thread->tid;
  //initial_thread->sema=&sema_now;
  initial_thread->parent_sema=NULL;
  initial_thread->parent=NULL;
 // initial_thread->ticks=0;
  initial_thread->nice=0;
  initial_thread->recent_cpu=0;
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore start_idle;
  sema_init (&start_idle, 0);
  thread_create ("idle", PRI_MIN, idle, &start_idle);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&start_idle);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
unsigned long long ready_num;
void
thread_tick (void) 
{
  struct thread *t = thread_current ();
  enum intr_level old_level;
  unsigned long long a, b;

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;


  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
#ifndef USERPROG
    if(thread_prior_aging==true)
		thread_aging();
#endif

  old_level = intr_disable ();
//  if(++thread_ticks22 >=TIMER_FREQ)
//	  thread_ticks22=0;

  if(thread_mlfqs && t != idle_thread)
	  (t->recent_cpu)=(t->recent_cpu)+(1<<14);
//printf(">> t2=%d\t", thread_ticks22);
/*  if(thread_mlfqs && thread_ticks22==0)//(thread_ticks%TIMER_FREQ==0))
  {
	  ready_num=(unsigned long long)list_size(&ready_list);
	  a=((unsigned long long)59<<28)/((unsigned long long)60<<14);
	  b=((unsigned long long)1<<28)/((unsigned long long)60<<14);
	  load_avg=( ((a*load_avg)>>14) + ((b*(ready_num<<14))>>14) );
//	  printf(">>> %llu\n", load_avg);
	  update_all(update_recent_cpu);	
  }*/

  if(thread_mlfqs && thread_ticks==1)//(thread_ticks%TIME_SLICE==0))//매 4마다.
	  update_priority(thread_current());
	  //update_all(update_priority);
  intr_set_level (old_level);
//  if(thread_mlfqs && thread_ticks==1)
//	  thread_yield();
}
void recent_cpu_()
{
//	struct thread * t=thread_current ();
	if(thread_mlfqs)
	{
		ready_num=(unsigned long long)list_size(&ready_list);
		if(thread_current ()!=idle_thread) ready_num++;
		load_avg=( ((aaa*load_avg)>>14) + ((bbb*(ready_num<<14))>>14) );
	//printf(">>> %llu\n", load_avg);
		update_all(update_recent_cpu);
		//t->recent_cpu=((((2*load_avg)<<14)/(2*load_avg+(1<<14))*(t->recent_cpu))>>14)+((t->nice)<<14);
	}
}
void thread_aging()
{
	struct list_elem * tmp_e;
	struct thread * tmp_t;
	for(tmp_e=list_begin(&ready_list); tmp_e !=list_end(&ready_list); tmp_e=list_next(tmp_e))
	{
		tmp_t=list_entry(tmp_e, struct thread, elem);
		(tmp_t->priority)++;
	}
}
/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;
  struct thread *p;


  ASSERT (function != NULL);
  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  //printf(">>>>>>>>>%s\n",name);
  init_thread (t, name, priority);//list_init(&t->child)을 내부에서 해준다. 딴것도...
  tid = t->tid = allocate_tid ();
  //rindid modi
	//sema_now=(struct semaphore*)malloc(sizeof(struct semaphore));
//	sema_init (&t->sema, 0);//
//	sema_init (&t->i_am_making_thread, 0);
	//부모 thread가 없는 경우를 예외처리 해야하나?
	p=thread_current();
	t->parent_sema = &(p->sema);
	t->parent=p;
	(t->i_am_child)=(struct child_elem *)malloc(sizeof(struct child_elem));
	(t->i_am_child)->tid=tid;
	(t->i_am_child)->is_alive=1;
	(t->i_am_child)->child_error_code=0;
	list_push_back(&t->parent->child , &t->i_am_child->elem);
	t->wait_tid=0;
	t->nice=p->nice;
	t->recent_cpu=p->recent_cpu;
	t->not_cpu=0;
	

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

  /* Add to run queue. */
  thread_unblock (t);
  thread_yield();

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_push_back (&ready_list, &t->elem);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  struct thread *cur = thread_current ();
  struct list_elem * tmp_e;
  struct list_elem * tmp_ne;
  struct child_elem * tmp_ce;

  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  //rindid_modi remove child
  for(tmp_e=list_begin(&cur->child); tmp_e !=list_end(&cur->child);)
  {
	tmp_ce=list_entry(tmp_e, struct child_elem, elem);
	tmp_ne=list_next(tmp_e);
	list_remove(tmp_e);
	tmp_e=tmp_ne;
	free(tmp_ce);
  }
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());
  old_level = intr_disable ();
  if (cur != idle_thread) 
    list_push_back (&ready_list, &cur->elem);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  enum intr_level old_level;
  old_level = intr_disable ();
  thread_current ()->priority = new_priority;
  intr_set_level (old_level);

  thread_yield();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
	thread_current ()->nice=nice;
	if(thread_mlfqs) update_priority(thread_current());
	//thread_yield();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current ()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
//printf(">>> %d\n", ready_num=(unsigned long long)list_size(&ready_list));
  return (load_avg*100)>>14;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  return (thread_current ()-> recent_cpu*100)>>14;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  //rindid_modi
 // hex_dump(name, name, 500, true);
 // printf(">>>> len = %d\n", strlen(name));
  strlcpy (t->name, name, strlen(name)+1);
 // printf("ffffffff[%s]\n",t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->priority_old=-100;
  t->magic = THREAD_MAGIC;
  list_push_back (&all_list, &t->allelem);

  //rindid modi
  t->child_load_fail=0;
  list_init(&t->child);
  sema_init (&t->sema, 0);//
  sema_init (&t->i_am_making_thread, 0);
  //부모 thread가 없는 경우를 예외처리 해야하나?
  ////t->sema=sema_now;
  //t->parent_sema = &(thread_current()->sema);
  //t->parent=thread_current();
  //(t->i_am_child).tid=tid;
  /*
  (t->i_am_child)=(struct child_elem *)malloc(sizeof(struct child_elem));
  (t->i_am_child)->is_alive=1;
  (t->i_am_child)->child_error_code=-1;*/
  //list_push_back(&t->parent->child , &t->i_am_child.elem);
  //t->wait_tid=0;
//  sema_init(&t->sema, 0);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  struct list_elem * tmp_e;
  struct thread * tmp_t;
  struct list_elem * next=NULL;
  int next_priority=-64;

  if (list_empty (&ready_list))
    return idle_thread;
  else
  {
   // return list_entry (list_pop_front (&ready_list), struct thread, elem);
   // rindid_modi
	for(tmp_e=list_begin(&ready_list); tmp_e !=list_end(&ready_list); tmp_e=list_next(tmp_e))
	{
		tmp_t=list_entry(tmp_e, struct thread, elem);
		if(thread_mlfqs) update_priority(tmp_t);
		if(next==NULL || tmp_t->priority > next_priority)
		{
			next_priority=tmp_t->priority;
			next=tmp_e;
		}
	}
	tmp_t=list_entry (next, struct thread, elem);
	tmp_t->not_cpu=0;
	list_remove(next);
	return tmp_t;
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
int preeeee=0;
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
/*  if(cur!=NULL && next!=NULL && preeeee!=next->tid)
  printf(">>> cur=%d, cur_pr=%d, nextlist is %p, %d, next_pr=%d\n", cur->tid,cur->priority,next, next->tid, next->priority);
if(next!=NULL)preeeee=next->tid;*/
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
//rindid_modi
struct list_elem * ttemp_e;
struct list_elem * ttttemp_e;
struct block_elem * ttemp_b;
struct thread * ttemp_t;
void update_all(void update_func(struct thread * ))
{
    //block
    for(ttemp_e=list_begin(&block_list);ttemp_e!=list_end(&block_list);ttemp_e=list_next(ttemp_e))
    {
        ttemp_b=list_entry(ttemp_e, struct block_elem, elem);
        ttemp_t=ttemp_b->my_thread;
        update_func(ttemp_t);
    }
    //ready
    for(ttemp_e=list_begin(&ready_list);ttemp_e!=list_end(&ready_list);ttemp_e=list_next(ttemp_e))
    {
        ttemp_t=list_entry(ttemp_e, struct thread, elem);
        update_func(ttemp_t);
    }
    //current
    ttemp_t=thread_current();
    update_func(ttemp_t);
}
void update_priority(struct thread * t)
{
    unsigned long long r_cpu=0;//(t->recent_cpu/4)
    r_cpu=t->recent_cpu;
    r_cpu=r_cpu<<1;
    r_cpu=r_cpu>>15;
	r_cpu=r_cpu/4;
	if((t->recent_cpu)>2147483648)
		t->priority=PRI_MAX+r_cpu-(t->nice*2);
	else
		t->priority=PRI_MAX-r_cpu-(t->nice*2);
	if(t->priority > PRI_MAX) t->priority = PRI_MAX;
	if(t->priority < PRI_MIN) t->priority = PRI_MIN;
}
void update_recent_cpu(struct thread * t)
{
	unsigned long long nice2;
	if((t->nice)>=0) nice2=(t->nice)<<14;
	else 
	{
		nice2=(-(t->nice));
		nice2=nice2<<14;
		nice2=2147483648 + nice2;
	}
	t->recent_cpu=((((2*load_avg)<<14)/(2*load_avg+(1<<14))*(t->recent_cpu))>>14)+nice2;
}
