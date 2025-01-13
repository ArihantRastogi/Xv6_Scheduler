#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "syscall.h"

static unsigned int seed = 123456;

unsigned int rand() {

  seed = seed * 1664525 + 1013904223;
  return seed;
}

// mapping for syscall mask to syscall name
char* syscall_name(int mask) {
  switch(mask) {
    case 1 << SYS_fork: return "fork";
    case 1 << SYS_exit: return "exit";
    case 1 << SYS_wait: return "wait";
    case 1 << SYS_pipe: return "pipe";
    case 1 << SYS_read: return "read";
    case 1 << SYS_kill: return "kill";
    case 1 << SYS_exec: return "exec";
    case 1 << SYS_fstat: return "fstat";
    case 1 << SYS_chdir: return "chdir";
    case 1 << SYS_dup: return "dup";
    case 1 << SYS_getpid: return "getpid";
    case 1 << SYS_sbrk: return "sbrk";
    case 1 << SYS_sleep: return "sleep";
    case 1 << SYS_uptime: return "uptime";
    case 1 << SYS_open: return "open";
    case 1 << SYS_write: return "write";
    case 1 << SYS_mknod: return "mknod";
    case 1 << SYS_unlink: return "unlink";
    case 1 << SYS_link: return "link";
    case 1 << SYS_mkdir: return "mkdir";
    case 1 << SYS_close: return "close";
    case 1 << SYS_getsyscount: return "getsyscount";
    default: return "unknown";
  }
}

struct cpu cpus[NCPU];

struct proc proc[NPROC];

struct proc *mlfq[PRIORITY_QUEUES][NPROC];
int queue_counts[PRIORITY_QUEUES] = {0};
int queue_ticks[PRIORITY_QUEUES] = {1,4,8,16};
struct spinlock queue_lock;

struct proc *initproc;

int nextpid = 1;
struct spinlock pid_lock;

extern void forkret(void);
static void freeproc(struct proc *p);

extern char trampoline[]; // trampoline.S

// helps ensure that wakeups of wait()ing
// parents are not lost. helps obey the
// memory model when using p->parent.
// must be acquired before any p->lock.
struct spinlock wait_lock;

// Allocate a page for each process's kernel stack.
// Map it high in memory, followed by an invalid
// guard page.
void proc_mapstacks(pagetable_t kpgtbl)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    char *pa = kalloc();
    if (pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int)(p - proc));
    kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  }
}

void enqueue_process(struct proc *p, int queue_no)
{
  if (queue_no < 0 || queue_no >= PRIORITY_QUEUES) {
    // printf("Invalid queue number\n");
    return;
  }
  if (queue_counts[queue_no] >= NPROC) {
    // printf("Queue is already full\n");
    return;
  }
  if(p->state != RUNNABLE) // only enqueue_process runnable processes
		return;
  acquire(&queue_lock);
	for(int i = 0; i<queue_counts[queue_no]; i++){ // check if already in queue
		if(mlfq[queue_no][i]->pid == p->pid){
      release(&queue_lock); 
			return;
    }
  }
	p->currq = queue_no;
  int pos = queue_counts[queue_no]++;
	mlfq[queue_no][pos] = p;
  release(&queue_lock); 
	return;
}

void dequeue_process(struct proc *p, int queue_no)
{
  if (queue_no < 0 || queue_no >= PRIORITY_QUEUES) {
    // printf("Invalid queue number\n");
    return;
  }
  acquire(&queue_lock);
  if(queue_counts[queue_no] == 0){ // if queue is empty
    release(&queue_lock); 
    return;
  }
  for(int i = 0; i < queue_counts[queue_no];i++){
    if(mlfq[queue_no][i]->pid == p->pid){
      mlfq[queue_no][i] = 0;
      for(int j = i; j<queue_counts[queue_no]-1; j++){
				mlfq[queue_no][j] = mlfq[queue_no][j+1];
			}
			queue_counts[queue_no] -= 1;
      release(&queue_lock);
			return;
    }
  }
  release(&queue_lock); 
  return;
}

// initialize the proc table.
void procinit(void)
{
  struct proc *p;

  initlock(&pid_lock, "nextpid");
  initlock(&wait_lock, "wait_lock");
  initlock(&queue_lock, "queue_lock");
  for (p = proc; p < &proc[NPROC]; p++)
  {
    initlock(&p->lock, "proc");
    p->state = UNUSED;
    p->kstack = KSTACK((int)(p - proc));
  }
}

// Must be called with interrupts disabled,
// to prevent race with process being moved
// to a different CPU.
int cpuid()
{
  int id = r_tp();
  return id;
}

// Return this CPU's cpu struct.
// Interrupts must be disabled.
struct cpu *
mycpu(void)
{
  int id = cpuid();
  struct cpu *c = &cpus[id];
  return c;
}

// Return the current struct proc *, or zero if none.
struct proc *
myproc(void)
{
  push_off();
  struct cpu *c = mycpu();
  struct proc *p = c->proc;
  pop_off();
  return p;
}

int allocpid()
{
  int pid;

  acquire(&pid_lock);
  pid = nextpid;
  nextpid = nextpid + 1;
  release(&pid_lock);

  return pid;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, or a memory allocation fails, return 0.
static struct proc *
allocproc(void)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->state == UNUSED)
    {
      goto found;
    }
    else
    {
      release(&p->lock);
    }
  }
  return 0;

found:
  p->pid = allocpid();
  p->state = USED;

  // Allocate a trapframe page.
  if ((p->trapframe = (struct trapframe *)kalloc()) == 0)
  {
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  if (p->pagetable == 0)
  {
    freeproc(p);
    release(&p->lock);
    return 0;
  }
  p->rtime = 0;
  p->etime = 0;
  p->ctime = ticks;
  //----------------------------------------------------------------------------------------------//
  // Additions for Part 1
  p->mask = 0;
  for (int i = 0; i < 32; i++) {
    p->syscall_counts[i] = 0;
  }
  p->alarmticks = 0;
  p->alarmhandler = 0;
  p->tickcount = 0;
  p->in_handler = 0;
  p->backup_tf = 0;
  //----------------------------------------------------------------------------------------------//
  // Additions for Part 2
  p->tickets = 1;  // Default 1 ticket
  p->arrival_time = ticks;
  p->curr_ticks = 0;
  p->currq = 0;
  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context));
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;
  
  return p;
}

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if (p->trapframe)
    kfree((void *)p->trapframe);
  p->trapframe = 0;
  if (p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
}

// Create a user page table for a given process, with no user memory,
// but with trampoline and trapframe pages.
pagetable_t
proc_pagetable(struct proc *p)
{
  pagetable_t pagetable;

  // An empty page table.
  pagetable = uvmcreate();
  if (pagetable == 0)
    return 0;

  // map the trampoline code (for system call return)
  // at the highest user virtual address.
  // only the supervisor uses it, on the way
  // to/from user space, so not PTE_U.
  if (mappages(pagetable, TRAMPOLINE, PGSIZE,
               (uint64)trampoline, PTE_R | PTE_X) < 0)
  {
    uvmfree(pagetable, 0);
    return 0;
  }

  // map the trapframe page just below the trampoline page, for
  // trampoline.S.
  if (mappages(pagetable, TRAPFRAME, PGSIZE,
               (uint64)(p->trapframe), PTE_R | PTE_W) < 0)
  {
    uvmunmap(pagetable, TRAMPOLINE, 1, 0);
    uvmfree(pagetable, 0);
    return 0;
  }

  return pagetable;
}

// Free a process's page table, and free the
// physical memory it refers to.
void proc_freepagetable(pagetable_t pagetable, uint64 sz)
{
  uvmunmap(pagetable, TRAMPOLINE, 1, 0);
  uvmunmap(pagetable, TRAPFRAME, 1, 0);
  uvmfree(pagetable, sz);
}

// a user program that calls exec("/init")
// assembled from ../user/initcode.S
// od -t xC ../user/initcode
uchar initcode[] = {
    0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x45, 0x02,
    0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x35, 0x02,
    0x93, 0x08, 0x70, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x93, 0x08, 0x20, 0x00, 0x73, 0x00, 0x00, 0x00,
    0xef, 0xf0, 0x9f, 0xff, 0x2f, 0x69, 0x6e, 0x69,
    0x74, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

// Set up first user process.
void userinit(void)
{
  struct proc *p;

  p = allocproc();
  initproc = p;

  // allocate one user page and copy initcode's instructions
  // and data into it.
  uvmfirst(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;     // user program counter
  p->trapframe->sp = PGSIZE; // user stack pointer

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;

  #ifdef MLFQ
    enqueue_process(p, 0);
  #endif

  release(&p->lock);
}

// Grow or shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int growproc(int n)
{
  uint64 sz;
  struct proc *p = myproc();

  sz = p->sz;
  if (n > 0)
  {
    if ((sz = uvmalloc(p->pagetable, sz, sz + n, PTE_W)) == 0)
    {
      return -1;
    }
  }
  else if (n < 0)
  {
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if ((np = allocproc()) == 0)
  {
    return -1;
  }

  // Copy user memory from parent to child.
  if (uvmcopy(p->pagetable, np->pagetable, p->sz) < 0)
  {
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for (i = 0; i < NOFILE; i++)
    if (p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  safestrcpy(np->name, p->name, sizeof(p->name));

  np->mask = 0;  // Set mask of child to 0  ---------------------------------------------------------------
  pid = np->pid;
  np->tickets = p->tickets;

  release(&np->lock);

  acquire(&wait_lock);
  np->parent = p;
  release(&wait_lock);

  acquire(&np->lock);
  np->state = RUNNABLE;
  #ifdef MLFQ
  enqueue_process(np, 0);
  np->currq = 0;
  np->curr_ticks = 0;
  #endif
  release(&np->lock);

  return pid;
}

// Pass p's abandoned children to init.
// Caller must hold wait_lock.
void reparent(struct proc *p)
{
  struct proc *pp;

  for (pp = proc; pp < &proc[NPROC]; pp++)
  {
    if (pp->parent == p)
    {
      pp->parent = initproc;
      wakeup(initproc);
    }
  }
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait().
void exit(int status)
{
  struct proc *p = myproc();

  if (p == initproc)
    panic("init exiting");

  // Close all open files.
  for (int fd = 0; fd < NOFILE; fd++)
  {
    if (p->ofile[fd])
    {
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(p->cwd);
  end_op();
  p->cwd = 0;
  // Addition for Part 1 - printing the syscall_counts when getsyscount exits
  if (p->parent != 0) // Make sure the child has a parent
  {
    acquire(&p->parent->lock); // Lock the parent's process to prevent race conditions

    for (int i = 0; i < 32; i++) {
      // Add the child's syscall counts to the parent's syscall counts
      p->parent->syscall_counts[i] += p->syscall_counts[i];
    }

    release(&p->parent->lock); // Release the lock after updating
  }
  if (p->mask != 0 && p->parent != 0) {
    int syscall_index = 0;
    for (int i = 0; i < 32; i++) {
      if (p->mask & (1 << i)) {
        syscall_index = i;
        break;
      }
    }
    printf("PID %d called %s %d times.\n", p->pid, syscall_name(1 << syscall_index), p->syscall_counts[syscall_index]);
  }
  acquire(&wait_lock);

  // Give any children to init.
  reparent(p);

  // Parent might be sleeping in wait().
  wakeup(p->parent);

  acquire(&p->lock);

  p->xstate = status;
  p->state = ZOMBIE;
  p->etime = ticks;

  release(&wait_lock);

  // Jump into the scheduler, never to return.
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int wait(uint64 addr)
{
  struct proc *pp;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for (;;)
  {
    // Scan through table looking for exited children.
    havekids = 0;
    for (pp = proc; pp < &proc[NPROC]; pp++)
    {
      if (pp->parent == p)
      {
        // make sure the child isn't still in exit() or swtch().
        acquire(&pp->lock);

        havekids = 1;
        if (pp->state == ZOMBIE)
        {
          // Found one.
          pid = pp->pid;
          if (addr != 0 && copyout(p->pagetable, addr, (char *)&pp->xstate,
                                   sizeof(pp->xstate)) < 0)
          {
            release(&pp->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(pp);
          release(&pp->lock);
          release(&wait_lock);
          return pid;
        }
        release(&pp->lock);
      }
    }

    // No point waiting if we don't have any children.
    if (!havekids || killed(p))
    {
      release(&wait_lock);
      return -1;
    }

    // Wait for a child to exit.
    sleep(p, &wait_lock); // DOC: wait-sleep
  }
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();

  c->proc = 0;
  for (;;)
  {
    // Avoid deadlock by ensuring that devices can interrupt.
    intr_on();
    #ifdef MLFQ
    for(p = proc; p < &proc[NPROC]; p++){ // enqueue_process all RUNNABLE processes to the mlfq
      if(p->state == RUNNABLE){
        enqueue_process(p, p->currq);
      }
    }
    struct proc* proc_to_be_scheduled = 0; // process to be scheduled
    for(int j=0;j<PRIORITY_QUEUES;j++){
      if(queue_counts[j] > 0){
        proc_to_be_scheduled = mlfq[j][0];
        dequeue_process(proc_to_be_scheduled, j);
        break;
      }
    }
    if(proc_to_be_scheduled != 0){
      acquire(&proc_to_be_scheduled->lock);
      if(proc_to_be_scheduled->state == RUNNABLE){
        proc_to_be_scheduled->state = RUNNING;
        c->proc = proc_to_be_scheduled;
        swtch(&c->context, &proc_to_be_scheduled->context);
        c->proc = 0;
      }
      release(&proc_to_be_scheduled->lock);
    }
    #endif
    #ifdef LBS
    int total_tickets = 0;

    // Calculate the total number of tickets of all RUNNABLE processes
    for(p = proc; p < &proc[NPROC]; p++){
      acquire(&p->lock);
      if(p->state == RUNNABLE) {
        total_tickets += p->tickets;
      }
      release(&p->lock);
    }

    if(total_tickets > 0){
      // Generate a random number between 0 and total_tickets - 1
      int winning_ticket = rand() % total_tickets;
      int ticket_counter = 0;
      struct proc *winner = 0;
      struct proc *potential_winner = 0;    

      // Find the process that owns the winning ticket
      for(p = proc; p < &proc[NPROC]; p++){
        acquire(&p->lock);
        if(p->state == RUNNABLE) {
          ticket_counter += p->tickets;
          if(ticket_counter > winning_ticket) {
            if(potential_winner == 0 || (p->tickets == potential_winner->tickets && p->arrival_time < potential_winner->arrival_time)) {
              potential_winner = p;
            }
          }
        }
        release(&p->lock);
      }
      int x = 0;
      int y = 0;
      if(potential_winner) {
        winner = potential_winner;
        x = potential_winner->tickets;
        y = potential_winner->arrival_time;
      }

      for(p = proc; p < &proc[NPROC]; p++) {
        acquire(&p->lock);
        if(p->state == RUNNABLE && p->tickets == x && p->arrival_time < y) {
          winner = p;
        }
        release(&p->lock);
      }
      // Switch to the winning process
      if(winner) {
        acquire(&winner->lock);
        if(winner->state == RUNNABLE) {
          winner->state = RUNNING;
          c->proc = winner;
          swtch(&c->context, &winner->context);
          c->proc = 0;
        }
        release(&winner->lock);
      }
    }
    #endif
    #ifdef DEFAULT
      for (p = proc; p < &proc[NPROC]; p++)
      {
        acquire(&p->lock);
        if (p->state == RUNNABLE)
        {
          // Switch to chosen process.  It is the process's job
          // to release its lock and then reacquire it
          // before jumping back to us.
          p->state = RUNNING;
          c->proc = p;
          swtch(&c->context, &p->context);

          // Process is done running for now.
          // It should have changed its p->state before coming back.
          c->proc = 0;
        }
        release(&p->lock);
      }
    #endif
  }
}

// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void sched(void)
{
  int intena;
  struct proc *p = myproc();

  if (!holding(&p->lock))
    panic("sched p->lock");
  if (mycpu()->noff != 1)
    panic("sched locks");
  if (p->state == RUNNING)
    panic("sched running");
  if (intr_get())
    panic("sched interruptible");

  intena = mycpu()->intena;
  swtch(&p->context, &mycpu()->context);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void yield(void)
{
  struct proc *p = myproc();
  acquire(&p->lock);
  p->state = RUNNABLE;
  sched();
  release(&p->lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch to forkret.
void forkret(void)
{
  static int first = 1;

  // Still holding p->lock from scheduler.
  release(&myproc()->lock);

  if (first)
  {
    // File system initialization must be run in the context of a
    // regular process (e.g., because it calls sleep), and thus cannot
    // be run from main().
    first = 0;
    fsinit(ROOTDEV);
  }

  usertrapret();
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();

  // Must acquire p->lock in order to
  // change p->state and then call sched.
  // Once we hold p->lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup locks p->lock),
  // so it's okay to release lk.

  acquire(&p->lock); // DOC: sleeplock1
  release(lk);

  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;
  #ifdef MLFQ
    dequeue_process(p, p->currq);
  #endif

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  release(&p->lock);
  acquire(lk);
}

// Wake up all processes sleeping on chan.
// Must be called without any p->lock.
void wakeup(void *chan)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    if (p != myproc())
    {
      acquire(&p->lock);
      if (p->state == SLEEPING && p->chan == chan)
      {
        p->state = RUNNABLE;
      }
      release(&p->lock);
    }
  }
}

// Kill the process with the given pid.
// The victim won't exit until it tries to return
// to user space (see usertrap() in trap.c).
int kill(int pid)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->pid == pid)
    {
      p->killed = 1;
      #ifdef MLFQ 
        dequeue_process(p, p->currq);
      #endif
      if (p->state == SLEEPING)
      {
        // Wake process from sleep().
        p->state = RUNNABLE;
      }
      release(&p->lock);
      return 0;
    }
    release(&p->lock);
  }
  return -1;
}

void setkilled(struct proc *p)
{
  acquire(&p->lock);
  p->killed = 1;
  release(&p->lock);
}

int killed(struct proc *p)
{
  int k;

  acquire(&p->lock);
  k = p->killed;
  release(&p->lock);
  return k;
}

// Copy to either a user address, or kernel address,
// depending on usr_dst.
// Returns 0 on success, -1 on error.
int either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  struct proc *p = myproc();
  if (user_dst)
  {
    return copyout(p->pagetable, dst, src, len);
  }
  else
  {
    memmove((char *)dst, src, len);
    return 0;
  }
}

// Copy from either a user address, or kernel address,
// depending on usr_src.
// Returns 0 on success, -1 on error.
int either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  struct proc *p = myproc();
  if (user_src)
  {
    return copyin(p->pagetable, dst, src, len);
  }
  else
  {
    memmove(dst, (char *)src, len);
    return 0;
  }
}

// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void procdump(void)
{
  static char *states[] = {
      [UNUSED] "unused",
      [USED] "used",
      [SLEEPING] "sleep ",
      [RUNNABLE] "runble",
      [RUNNING] "run   ",
      [ZOMBIE] "zombie"};
  struct proc *p;
  char *state;

  printf("\n");
  for (p = proc; p < &proc[NPROC]; p++)
  {
    if (p->state == UNUSED)
      continue;
    if (p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    printf("%d %s %s", p->pid, state, p->name);
    printf("\n");
  }
}

// waitx
int waitx(uint64 addr, uint *wtime, uint *rtime)
{
  struct proc *np;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for (;;)
  {
    // Scan through table looking for exited children.
    havekids = 0;
    for (np = proc; np < &proc[NPROC]; np++)
    {
      if (np->parent == p)
      {
        // make sure the child isn't still in exit() or swtch().
        acquire(&np->lock);

        havekids = 1;
        if (np->state == ZOMBIE)
        {
          // Found one.
          pid = np->pid;
          *rtime = np->rtime;
          *wtime = np->etime - np->ctime - np->rtime;
          if (addr != 0 && copyout(p->pagetable, addr, (char *)&np->xstate,
                                   sizeof(np->xstate)) < 0)
          {
            release(&np->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(np);
          release(&np->lock);
          release(&wait_lock);
          return pid;
        }
        release(&np->lock);
      }
    }

    // No point waiting if we don't have any children.
    if (!havekids || p->killed)
    {
      release(&wait_lock);
      return -1;
    }

    // Wait for a child to exit.
    sleep(p, &wait_lock); // DOC: wait-sleep
  }
}

void update_time()
{
  struct proc *p;
  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->state == RUNNING)
    {
      p->rtime++;
    }
    // #ifdef MLFQ
    // if (p->pid>=3 && p->pid <=13)
    //   printf("%d %d %d\n", p->pid, ticks, p->currq);
    // #endif
    release(&p->lock);
  }
}