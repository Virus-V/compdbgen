/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, virusv@live.com
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* clang-format off */
#include <sys/cdefs.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <linux/ptrace.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <dirent.h>
#include <fcntl.h>

#include "cjson/cJSON.h"
#include "compdbgen.h"
/* clang-format on */

/* Linux ptrace event definitions if not available */
#ifndef PTRACE_EVENT_FORK
#define PTRACE_EVENT_FORK 1
#endif
#ifndef PTRACE_EVENT_VFORK
#define PTRACE_EVENT_VFORK 2
#endif
#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif
#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC 4
#endif

#define nitems(x) (sizeof((x)) / sizeof((x)[0]))

typedef uintptr_t psaddr_t;

/* Linux page definitions */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE - 1))
#endif

struct procabi_table {
  const char *name;
  struct procabi *abi;
};

/* External regex variables from main.c */
extern regex_t *regex_exec_cmds;
extern regex_t *regex_src_suffix;

static void enter_syscall(struct glbctx *, struct threadinfo *, void *);
static void new_proc(struct glbctx *, pid_t, pid_t);

static struct procabi freebsd = {.type = "FreeBSD",
                                 .pointer_size = sizeof(void *)};

#if !defined(__SIZEOF_POINTER__)
#error "Use a modern compiler."
#endif

#if __SIZEOF_POINTER__ > 4
static struct procabi freebsd32 = {.type = "FreeBSD32",
                                   .pointer_size = sizeof(uint32_t),
                                   .compat_prefix = "freebsd32_"};
#endif

static struct procabi linux_abi = {.type = "Linux", .pointer_size = sizeof(void *)};

#if __SIZEOF_POINTER__ > 4
static struct procabi linux32 = {.type = "Linux32",
                                 .pointer_size = sizeof(uint32_t)};
#endif

static struct procabi_table abis[] = {
#if __SIZEOF_POINTER__ == 4
    {"FreeBSD ELF32", &freebsd},
#elif __SIZEOF_POINTER__ == 8
    {"FreeBSD ELF64", &freebsd},
    {"FreeBSD ELF32", &freebsd32},
#else
#error "Unsupported pointer size"
#endif
#if defined(__powerpc64__)
    {"FreeBSD ELF64 V2", &freebsd},
#endif
#if defined(__amd64__)
    {"FreeBSD a.out", &freebsd32},
#endif
#if defined(__i386__)
    {"FreeBSD a.out", &freebsd},
#endif
#if __SIZEOF_POINTER__ >= 8
    {"Linux ELF64", &linux_abi},        {"Linux ELF32", &linux32},
#else
    {"Linux ELF32", &linux_abi},
#endif
};

void setup_and_wait(struct glbctx *info, char *command[]) {
  pid_t pid;

  pid = vfork();
  if (pid == -1) {
    err(1, "fork failed");
  }

  if (pid == 0) { /* Child */
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execvp(command[0], command);
    err(1, "execvp %s", command[0]);
  }

  /* Only in the parent here */
  if (waitpid(pid, NULL, 0) < 0) {
    err(1, "unexpected stop in waitpid");
  }

  /* Set ptrace options for the initial process */
  if (ptrace(PTRACE_SETOPTIONS, pid, NULL, 
             PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC) == -1) {
    err(1, "Unable to set ptrace options for initial pid %ld", (long)pid);
  }

  new_proc(info, pid, 0);
}

/*
 * Determine the ABI.  This is called after every exec, and when
 * a process is first monitored.
 */
static struct procabi *find_abi(pid_t pid) {
  unsigned int i;
  char progt[32] = "Linux ELF64";
  
  /* For simplicity, assume 64-bit Linux for now */
  /* Could be enhanced by reading ELF headers from /proc/PID/exe */
  for (i = 0; i < nitems(abis); i++) {
    if (strcmp(abis[i].name, progt) == 0)
      return (abis[i].abi);
  }
  warnx("ABI %s for pid %ld is not supported", progt, (long)pid);
  return (NULL);
}

static struct threadinfo *new_thread(struct procinfo *p, pid_t lwpid) {
  struct threadinfo *nt;

  LIST_FOREACH(nt, &p->threadlist, entries) {
    if (nt->tid == lwpid) {
      errx(1, "Duplicate thread for LWP %ld", (long)lwpid);
    }
  }

  nt = calloc(1, sizeof(struct threadinfo));
  if (nt == NULL) {
    err(1, "calloc() failed");
  }

  nt->proc = p;
  nt->tid = lwpid;
  LIST_INSERT_HEAD(&p->threadlist, nt, entries);
  return (nt);
}

static void free_thread(struct threadinfo *t) {
  LIST_REMOVE(t, entries);
  free(t);
}

static void add_threads(struct glbctx *info, struct procinfo *p) {
  struct threadinfo *t;
  
  /* On Linux, processes have a single main thread initially */
  /* We'll track threads as they're created via clone/fork */
  t = new_thread(p, p->pid);
  info->curthread = t;
}

static void new_proc(struct glbctx *info, pid_t pid, pid_t lwpid) {
  struct procinfo *np;

  LIST_FOREACH(np, &info->proclist, entries) {
    if (np->pid == pid) {
      errx(1, "Duplicate process for pid %ld", (long)pid);
    }
  }

  np = calloc(1, sizeof(struct procinfo));
  np->pid = pid;
  np->abi = find_abi(pid);
  LIST_INIT(&np->threadlist);
  LIST_INSERT_HEAD(&info->proclist, np, entries);

  if (lwpid != 0) {
    new_thread(np, lwpid);
  } else {
    add_threads(info, np);
  }
}

static void free_proc(struct procinfo *p) {
  struct threadinfo *t, *t2;

  t = LIST_FIRST(&p->threadlist);
  while (t != NULL) {
    t2 = LIST_NEXT(t, entries);
    free(t);
    t = t2;
  }
  LIST_REMOVE(p, entries);
  free(p);
}

static struct procinfo *find_proc(struct glbctx *info, pid_t pid) {
  struct procinfo *np;

  LIST_FOREACH(np, &info->proclist, entries) {
    if (np->pid == pid) {
      return (np);
    }
  }

  return (NULL);
}

static void find_thread(struct glbctx *info, pid_t pid, pid_t lwpid) {
  struct procinfo *np;
  struct threadinfo *nt;

  np = find_proc(info, pid);
  assert(np != NULL);

  LIST_FOREACH(nt, &np->threadlist, entries) {
    if (nt->tid == lwpid) {
      info->curthread = nt;
      return;
    }
  }
  errx(1, "could not find thread");
}

static void find_exit_thread(struct glbctx *info, pid_t pid) {
  struct procinfo *p;

  p = find_proc(info, pid);
  assert(p != NULL);

  info->curthread = LIST_FIRST(&p->threadlist);
  assert(info->curthread != NULL);
  assert(LIST_NEXT(info->curthread, entries) == NULL);
}

/*
 * Copy a fixed amount of bytes from the process.
 */
static int get_struct(pid_t pid, psaddr_t offset, void *buf, size_t len) {
  long word;
  size_t i;
  char *p = buf;
  
  /* On Linux, we read memory word by word using PTRACE_PEEKDATA */
  for (i = 0; i < len; i += sizeof(long)) {
    errno = 0;
    word = ptrace(PTRACE_PEEKDATA, pid, offset + i, NULL);
    if (errno != 0) {
      return (-1);
    }
    
    size_t copy_size = (len - i < sizeof(long)) ? (len - i) : sizeof(long);
    memcpy(p + i, &word, copy_size);
  }
  return (0);
}

#define MAXSIZE 4096

/*
 * Copy a string from the process.  Note that it is
 * expected to be a C string, but if max is set, it will
 * only get that much.
 */
static char *get_string(pid_t pid, psaddr_t addr, int max) {
  char *buf, *nbuf;
  size_t offset, size, totalsize;
  long word;
  char *p;
  int i;

  offset = 0;
  if (max) {
    size = max + 1;
  } else {
    /* Read up to the end of the current page. */
    size = PAGE_SIZE - (addr % PAGE_SIZE);
    if (size > MAXSIZE) {
      size = MAXSIZE;
    }
  }
  totalsize = size;
  buf = malloc(totalsize);
  if (buf == NULL) {
    return (NULL);
  }

  for (;;) {
    /* Read memory word by word using PTRACE_PEEKDATA */
    for (i = 0; i < size; i += sizeof(long)) {
      errno = 0;
      word = ptrace(PTRACE_PEEKDATA, pid, addr + offset + i, NULL);
      if (errno != 0) {
        free(buf);
        return (NULL);
      }
      
      size_t copy_size = (size - i < sizeof(long)) ? (size - i) : sizeof(long);
      memcpy(buf + offset + i, &word, copy_size);
    }

    if (memchr(buf + offset, '\0', size) != NULL) {
      return (buf);
    }

    offset += size;
    if (totalsize < MAXSIZE && max == 0) {
      size = MAXSIZE - totalsize;
      if (size > PAGE_SIZE) {
        size = PAGE_SIZE;
      }
      nbuf = realloc(buf, totalsize + size);
      if (nbuf == NULL) {
        buf[totalsize - 1] = '\0';
        return (buf);
      }
      buf = nbuf;
      totalsize += size;
    } else {
      buf[totalsize - 1] = '\0';
      return (buf);
    }
  }
}

/*
 * Convert a 32-bit user-space pointer to psaddr_t by zero-extending.
 */
static psaddr_t user_ptr32_to_psaddr(int32_t user_pointer) {
  return ((psaddr_t)(uintptr_t)user_pointer);
}

static void get_string_array(struct glbctx *info, psaddr_t addr,
                             cJSON *array) {
  union {
    int32_t strarray32[PAGE_SIZE / sizeof(int32_t)];
    int64_t strarray64[PAGE_SIZE / sizeof(int64_t)];
    char buf[PAGE_SIZE];
  } u;
  char *string;
  size_t len;
  size_t pointer_size = info->curthread->proc->abi->pointer_size;
  pid_t pid = info->curthread->proc->pid;
  u_int i;

  fprintf(stderr, "DEBUG: get_string_array called with addr=%p, pointer_size=%zu\n", 
          (void*)addr, pointer_size);

  if ((addr % pointer_size) != 0) {
    fprintf(stderr, "DEBUG: Address not aligned, returning\n");
    return;
  }

  len = PAGE_SIZE - (addr % PAGE_SIZE);
  if (len > PAGE_SIZE) {
    len = PAGE_SIZE;
  }
  fprintf(stderr, "DEBUG: Reading %zu bytes from process %d at addr %p\n", len, pid, (void*)addr);
  if (get_struct(pid, addr, u.buf, len) == -1) {
    fprintf(stderr, "DEBUG: get_struct failed, returning\n");
    return;
  }
  fprintf(stderr, "DEBUG: Successfully read %zu bytes\n", len);
  assert(len > 0);

  i = 0;
  for (;;) {
    psaddr_t straddr;
    if (pointer_size == 4) {
      straddr = user_ptr32_to_psaddr(u.strarray32[i]);
    } else if (pointer_size == 8) {
      straddr = (psaddr_t)u.strarray64[i];
    } else {
      errx(1, "Unsupported pointer size: %zu", pointer_size);
    }

    /* Stop once we read the first NULL pointer. */
    if (straddr == 0)
      break;

    string = get_string(pid, straddr, 0);

    cJSON *arg = cJSON_CreateString(string);
    cJSON_AddItemToArray(array, arg);

    free(string);

    i++;
    if (i == len / pointer_size) {
      addr += len;
      len = PAGE_SIZE;
      if (get_struct(pid, addr, u.buf, len) == -1) {
        break;
      }
      i = 0;
    }
  }
}

static void enter_syscall(struct glbctx *info, struct threadinfo *t,
                          void *pl_ptr) {
  static int json_item_cnt = 0;
  struct user_regs_struct regs;
  struct {
    int pl_flags;
    int pl_syscall_code;
    int pl_syscall_narg;
  } *pl = pl_ptr;
  
  unsigned long args[6];
  u_int i, narg;

  /* Debug: Print all syscalls */
  fprintf(stderr, "DEBUG: Syscall %d from pid %d\n", pl->pl_syscall_code, t->proc->pid);

  /* ignore other syscall except execve */
  if (pl->pl_syscall_code != 59) {  /* Linux x86_64 execve */
    return;
  }
  
  fprintf(stderr, "DEBUG: Found execve call from pid %d\n", t->proc->pid);

  /* Get syscall arguments from registers */
  if (ptrace(PTRACE_GETREGS, t->tid, NULL, &regs) != 0) {
    fprintf(stderr, "DEBUG: Failed to get registers\n");
    goto _EXIT;
  }

#ifdef __x86_64__
  /* Linux x86_64 syscall arguments are in rdi, rsi, rdx, r10, r8, r9 */
  args[0] = regs.rdi;
  args[1] = regs.rsi;
  args[2] = regs.rdx;
  args[3] = regs.r10;
  args[4] = regs.r8;
  args[5] = regs.r9;
  
  fprintf(stderr, "DEBUG: execve args: filename=%p, argv=%p, envp=%p\n", 
          (void*)args[0], (void*)args[1], (void*)args[2]);
#elif defined(__i386__)
  /* Linux i386 syscall arguments are on the stack */
  args[0] = regs.ebx;
  args[1] = regs.ecx;
  args[2] = regs.edx;
  args[3] = regs.esi;
  args[4] = regs.edi;
  args[5] = regs.ebp;
#endif

  cJSON *arguments = cJSON_CreateArray();
  fprintf(stderr, "DEBUG: Getting argv from process memory\n");
  get_string_array(info, args[1], arguments);

  cJSON *enviroments = cJSON_CreateArray();
  fprintf(stderr, "DEBUG: Getting envp from process memory\n");
  get_string_array(info, args[2], enviroments);

  // check command matchs
  cJSON *argv0 = cJSON_GetArrayItem(arguments, 0);
  if (!argv0) {
    fprintf(stderr, "DEBUG: Failed to get argv[0]\n");
    goto _EXIT1;
  }
  
  const char *cmd_name = cJSON_GetStringValue(argv0);
  fprintf(stderr, "DEBUG: Command name: %s\n", cmd_name ? cmd_name : "NULL");
  
  if (!cmd_name) {
    fprintf(stderr, "DEBUG: Command name is NULL\n");
    goto _EXIT1;
  }

  regmatch_t m[2];

  int ret = regexec(regex_exec_cmds, cmd_name, 2, m, 0);
  if (ret) {
    if (ret != REG_NOMATCH) {
      err(1, "regex fail: %d\n", ret);
    }

    fprintf(stderr, "DEBUG: regex did not match command\n");
    goto _EXIT1;
  }
  
  fprintf(stderr, "DEBUG: Command regex matched!\n");

  char *directory = NULL;
  /* get PWD from enviroments */
  int cnt = cJSON_GetArraySize(enviroments);
  char *strtok_next;
  for (i = 0; i < cnt; i++) {
    char *env_str = cJSON_GetStringValue(cJSON_GetArrayItem(enviroments, i));
    if (env_str == NULL) {
      goto _EXIT1;
    }

    char *env_name = strtok_r(env_str, "=", &strtok_next);
    char *env_value = strtok_r(NULL, "=", &strtok_next);
    if (strcmp("PWD", env_name) == 0) {
      directory = strdup(env_value);
      break;
    }
  }

  if (directory == NULL) {
    goto _EXIT1;
  }

  /* check if contain vaild file */
  cnt = cJSON_GetArraySize(arguments);

  char *compile_file = NULL;
  struct stat fstat;
  for (i = cnt - 1; i > 0; i--) {
    char *file_str = cJSON_GetStringValue(cJSON_GetArrayItem(arguments, i));
    if (file_str == NULL || strlen(file_str) == 0) {
      goto _EXIT2;
    }

    regmatch_t src_m[2];
    ret = regexec(regex_src_suffix, file_str, 2, src_m, 0);
    if (ret) {
      if (ret != REG_NOMATCH) {
        err(1, "regex fail: %d\n", ret);
      }
      continue;
    }

    char *file_path = NULL;
    if (file_str[0] == '/') {
      asprintf(&file_path, "%s", file_str);
    } else {
      asprintf(&file_path, "%s/%s", directory, file_str);
    }

    if (file_path == NULL) {
      goto _EXIT2;
    }

    ret = stat(file_path, &fstat);
    if (ret != 0) {
      free(file_path);
      continue;
    }

    if (S_ISREG(fstat.st_mode)) {
      compile_file = strdup(file_path);
      free(file_path);
      break;
    }

    free(file_path);
  }

  if (compile_file == NULL) {
    goto _EXIT2;
  }

  if (json_item_cnt++ != 0) {
    fputs(",\n", info->outfile);
  }

  /* generate compile command database item */
  fprintf(info->outfile, "{\n\"directory\": \"%s\",\n", directory);
  fprintf(info->outfile, "\"file\": \"%s\",\n", compile_file);
  char *json_str = cJSON_PrintBuffered(arguments, 256, 1);
  fprintf(info->outfile, "\"arguments\": %s\n}", json_str);
  fflush(info->outfile);

  free(json_str);
  free(compile_file);

_EXIT2:
  free(directory);
_EXIT1:
  cJSON_Delete(arguments);
  cJSON_Delete(enviroments);
_EXIT:
  ;
}

/*
 * When a thread exits voluntarily (including when a thread calls
 * exit() to trigger a process exit), the thread's internal state
 * holds the arguments passed to the exit system call.  When the
 * thread's exit is reported, log that system call without a return
 * value.
 */
static void thread_exit_syscall(struct glbctx *info) {
  struct threadinfo *t;
}

void mainloop(struct glbctx *info) {
  int status;
  pid_t pid;
  struct user_regs_struct regs;
  int pending_signal = 0;

  while (!LIST_EMPTY(&info->proclist)) {
    pid = waitpid(-1, &status, __WALL);
    if (pid == -1) {
      if (errno == EINTR) {
        continue;
      }
      err(1, "Unexpected error from waitpid");
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      /* Process exited */
      find_exit_thread(info, pid);
      if (WIFEXITED(status)) {
        thread_exit_syscall(info);
      }

      free_proc(info->curthread->proc);
      info->curthread = NULL;
      continue;
    }

    if (WIFSTOPPED(status)) {
      int sig = WSTOPSIG(status);
      
      /* Handle ptrace events */
      if (sig == SIGTRAP) {
        int event = status >> 16;
        
        switch (event) {
        case PTRACE_EVENT_FORK:
        case PTRACE_EVENT_VFORK:
        case PTRACE_EVENT_CLONE:
          {
            pid_t new_pid;
            if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &new_pid) == -1) {
              err(1, "ptrace(PTRACE_GETEVENTMSG)");
            }
            new_proc(info, new_pid, 0);
            
            /* Set ptrace options for the new process */
            if (ptrace(PTRACE_SETOPTIONS, new_pid, NULL, 
                       PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC) == -1) {
              err(1, "Unable to set ptrace options for new pid %ld", (long)new_pid);
            }
          }
          break;
          
        case PTRACE_EVENT_EXEC:
          /* Process executed a new image */
          find_thread(info, pid, pid);
          if (info->curthread && info->curthread->proc) {
            info->curthread->proc->abi = find_abi(pid);
            if (info->curthread->proc->abi == NULL) {
              if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0)
                err(1, "Can not detach the process");
              free_proc(info->curthread->proc);
              info->curthread = NULL;
              continue;
            }
          }
          break;
          
        default:
          /* Check if this is a syscall stop */
          if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0) {
            find_thread(info, pid, pid);
            if (info->curthread) {
              /* Create a simple lwpinfo structure for syscall handling */
              struct {
                int pl_flags;
                int pl_syscall_code;
                int pl_syscall_narg;
              } pl;
              
              pl.pl_flags = 1; /* PL_FLAG_SCE */
              pl.pl_syscall_code = regs.orig_rax;
              pl.pl_syscall_narg = 6; /* Linux syscalls have max 6 args */
              
              enter_syscall(info, info->curthread, (void *)&pl);
            }
          }
          break;
        }
        pending_signal = 0;
      } else {
        pending_signal = sig;
      }
      
      ptrace(PTRACE_SYSCALL, pid, NULL, pending_signal);
    }
  }
}
