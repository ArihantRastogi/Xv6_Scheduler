#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  exit(n);
  return 0; // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return wait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if (growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  acquire(&tickslock);
  ticks0 = ticks;
  while (ticks - ticks0 < n)
  {
    if (killed(myproc()))
    {
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_waitx(void)
{
  uint64 addr, addr1, addr2;
  uint wtime, rtime;
  argaddr(0, &addr);
  argaddr(1, &addr1); // user virtual memory
  argaddr(2, &addr2);
  int ret = waitx(addr, &wtime, &rtime);
  struct proc *p = myproc();
  if (copyout(p->pagetable, addr1, (char *)&wtime, sizeof(int)) < 0)
    return -1;
  if (copyout(p->pagetable, addr2, (char *)&rtime, sizeof(int)) < 0)
    return -1;
  return ret;
}

// Addition for Part 1 - getsyscount
uint64
sys_getsyscount(void)
{
  int mask;
  struct proc *p = myproc();
  argint(0, &mask);
  p->mask = mask;
  return 0;
}
// Addition for Part 1 - sigalarm
uint64
sys_sigalarm(void) {
  int ticks;
  uint64 handler;

  // Get the arguments
  argint(0, &ticks);
  argaddr(1, &handler);
  if(ticks < 0) {
    return -1;
  }
  // Set the process's alarm parameters
  struct proc *p = myproc();
  p->alarmticks = ticks;
  p->alarmhandler = (void (*)())handler;
  p->tickcount = 0;

  return 0;
}
// Addition for Part 1 - sigreturn
uint64
sys_sigreturn(void) {
  struct proc *p = myproc();

  // Restore the backed-up trapframe
  memmove(p->trapframe, p->backup_tf, sizeof(struct trapframe));
  p->in_handler = 0;

  return p->trapframe->a0;  // register changed as test 3 failed
}
// Addition for Part 2 - settickets
uint64
sys_settickets(void)
{
  int number;
  argint(0, &number);
  struct proc *p = myproc();
  if(number < 1) return -1;  // Invalid number of tickets
  p->tickets = number;       // Set the new number of tickets
  return 0;
}