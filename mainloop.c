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
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <sys/procfs.h>

#include "cjson/cJSON.h"
#include "compdbgen.h"
/* clang-format on */

struct procabi_table {
  const char *name;
  struct procabi *abi;
};

static void enter_syscall(struct glbctx *, struct threadinfo *,
                          struct ptrace_lwpinfo *);
static void new_proc(struct glbctx *, pid_t, lwpid_t);

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

static struct procabi linux = {.type = "Linux", .pointer_size = sizeof(void *)};

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
    {"Linux ELF64", &linux},        {"Linux ELF32", &linux32},
#else
    {"Linux ELF32", &linux},
#endif
};

void setup_and_wait(struct glbctx *info, char *command[]) {
  pid_t pid;

  pid = vfork();
  if (pid == -1) {
    err(1, "fork failed");
  }

  if (pid == 0) { /* Child */
    ptrace(PT_TRACE_ME, 0, 0, 0);
    execvp(command[0], command);
    err(1, "execvp %s", command[0]);
  }

  /* Only in the parent here */
  if (waitpid(pid, NULL, 0) < 0) {
    err(1, "unexpected stop in waitpid");
  }

  new_proc(info, pid, 0);
}

/*
 * Determine the ABI.  This is called after every exec, and when
 * a process is first monitored.
 */
static struct procabi *find_abi(pid_t pid) {
  size_t len;
  unsigned int i;
  int error;
  int mib[4];
  char progt[32];

  len = sizeof(progt);
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_SV_NAME;
  mib[3] = pid;
  error = sysctl(mib, 4, progt, &len, NULL, 0);
  if (error != 0)
    err(2, "can not get sysvec name");

  for (i = 0; i < nitems(abis); i++) {
    if (strcmp(abis[i].name, progt) == 0)
      return (abis[i].abi);
  }
  warnx("ABI %s for pid %ld is not supported", progt, (long)pid);
  return (NULL);
}

static struct threadinfo *new_thread(struct procinfo *p, lwpid_t lwpid) {
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
  struct ptrace_lwpinfo pl;
  struct threadinfo *t;
  lwpid_t *lwps;
  int i, nlwps;

  nlwps = ptrace(PT_GETNUMLWPS, p->pid, NULL, 0);
  if (nlwps == -1) {
    err(1, "Unable to fetch number of LWPs");
  }
  assert(nlwps > 0);

  lwps = calloc(nlwps, sizeof(*lwps));
  nlwps = ptrace(PT_GETLWPLIST, p->pid, (caddr_t)lwps, nlwps);
  if (nlwps == -1) {
    err(1, "Unable to fetch LWP list");
  }

  for (i = 0; i < nlwps; i++) {
    t = new_thread(p, lwps[i]);
    if (ptrace(PT_LWPINFO, lwps[i], (caddr_t)&pl, sizeof(pl)) == -1) {
      err(1, "ptrace(PT_LWPINFO)");
    }

    if (pl.pl_flags & PL_FLAG_SCE) {
      info->curthread = t;
      enter_syscall(info, t, &pl);
    }
  }
  free(lwps);
}

static void new_proc(struct glbctx *info, pid_t pid, lwpid_t lwpid) {
  struct procinfo *np;

  LIST_FOREACH(np, &info->proclist, entries) {
    if (np->pid == pid) {
      errx(1, "Duplicate process for pid %ld", (long)pid);
    }
  }

  if (ptrace(PT_FOLLOW_FORK, pid, NULL, 1) == -1) {
    err(1, "Unable to follow forks for pid %ld", (long)pid);
  }

  if (ptrace(PT_LWP_EVENTS, pid, NULL, 1) == -1) {
    err(1, "Unable to enable LWP events for pid %ld", (long)pid);
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

  LIST_FOREACH_SAFE(t, &p->threadlist, entries, t2) { free(t); }
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

static void find_thread(struct glbctx *info, pid_t pid, lwpid_t lwpid) {
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
  struct ptrace_io_desc iorequest;

  iorequest.piod_op = PIOD_READ_D;
  iorequest.piod_offs = (void *)(uintptr_t)offset;
  iorequest.piod_addr = buf;
  iorequest.piod_len = len;
  if (ptrace(PT_IO, pid, (caddr_t)&iorequest, 0) < 0)
    return (-1);
  return (0);
}

#define MAXSIZE 4096

/*
 * Copy a string from the process.  Note that it is
 * expected to be a C string, but if max is set, it will
 * only get that much.
 */
static char *get_string(pid_t pid, psaddr_t addr, int max) {
  struct ptrace_io_desc iorequest;
  char *buf, *nbuf;
  size_t offset, size, totalsize;

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
    iorequest.piod_op = PIOD_READ_D;
    iorequest.piod_offs = (void *)((uintptr_t)addr + offset);
    iorequest.piod_addr = buf + offset;
    iorequest.piod_len = size;
    if (ptrace(PT_IO, pid, (caddr_t)&iorequest, 0) < 0) {
      free(buf);
      return (NULL);
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

  if (!__is_aligned(addr, pointer_size)) {
    return;
  }

  len = PAGE_SIZE - (addr & PAGE_MASK);
  if (get_struct(pid, addr, u.buf, len) == -1) {
    return;
  }
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
                          struct ptrace_lwpinfo *pl) {
  static int json_item_cnt = 0;
  struct syscall *sc;
  u_int i, narg;
#if defined(__FreeBSD_version) && __FreeBSD_version < 1400000
  register_t *args;
#else
  syscallarg_t *args;
#endif

  /* ignore other syscall except execve */
  if (pl->pl_syscall_code != SYS_execve) {
    return;
  }

#if defined(__FreeBSD_version) && __FreeBSD_version < 1400000
  args = calloc(pl->pl_syscall_narg, sizeof(register_t));
#else
  args = calloc(pl->pl_syscall_narg, sizeof(syscallarg_t));
#endif
  if (args == NULL) {
    err(1, "malloc syscall args failed\n");
  }

  if (ptrace(PT_GET_SC_ARGS, t->tid, (caddr_t)args,
#if defined(__FreeBSD_version) && __FreeBSD_version < 1400000
             sizeof(register_t) * pl->pl_syscall_narg) != 0) {
#else
             sizeof(syscallarg_t) * pl->pl_syscall_narg) != 0) {
#endif
    goto _EXIT;
  }

  cJSON *arguments = cJSON_CreateArray();
  get_string_array(info, args[1], arguments);

  cJSON *enviroments = cJSON_CreateArray();
  get_string_array(info, args[2], enviroments);

  // check command matchs
  cJSON *argv0 = cJSON_GetArrayItem(arguments, 0);
  assert(argv0 != NULL);

  extern regex_t *regex_exec_cmds;
  extern regex_t *regex_src_suffix;
  regmatch_t m[2];

  int ret = regexec(regex_exec_cmds, cJSON_GetStringValue(argv0), 2, m, 0);
  if (ret) {
    if (ret != REG_NOMATCH) {
      err(1, "regex fail: %d\n", ret);
    }

    goto _EXIT1;
  }

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

    ret = regexec(regex_src_suffix, file_str, 2, m, 0);
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
  free(args);
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

static void exit_syscall(struct glbctx *info, struct ptrace_lwpinfo *pl) {
  struct procinfo *p;

  /*
   * If the process executed a new image, check the ABI.  If the
   * new ABI isn't supported, stop tracing this process.
   */
  if (pl->pl_flags & PL_FLAG_EXEC) {
    assert(LIST_NEXT(LIST_FIRST(&p->threadlist), entries) == NULL);
    p->abi = find_abi(p->pid);
    if (p->abi == NULL) {
      if (ptrace(PT_DETACH, p->pid, (caddr_t)1, 0) < 0)
        err(1, "Can not detach the process");
      free_proc(p);
    }
  }
}

void mainloop(struct glbctx *info) {
  struct ptrace_lwpinfo pl;
  siginfo_t si;
  int pending_signal;

  while (!LIST_EMPTY(&info->proclist)) {
    if (waitid(P_ALL, 0, &si, WTRAPPED | WEXITED) == -1) {
      if (errno == EINTR) {
        continue;
      }
      err(1, "Unexpected error from waitid");
    }

    assert(si.si_signo == SIGCHLD);

    switch (si.si_code) {
    case CLD_EXITED:
    case CLD_KILLED:
    case CLD_DUMPED:
      find_exit_thread(info, si.si_pid);
      if (si.si_code == CLD_EXITED) {
        thread_exit_syscall(info);
      }

      free_proc(info->curthread->proc);
      info->curthread = NULL;
      break;
    case CLD_TRAPPED:
      if (ptrace(PT_LWPINFO, si.si_pid, (caddr_t)&pl, sizeof(pl)) == -1) {
        err(1, "ptrace(PT_LWPINFO)");
      }

      if (pl.pl_flags & PL_FLAG_CHILD) {
        new_proc(info, si.si_pid, pl.pl_lwpid);
        assert(LIST_FIRST(&info->proclist)->abi != NULL);
      } else if (pl.pl_flags & PL_FLAG_BORN) {
        new_thread(find_proc(info, si.si_pid), pl.pl_lwpid);
      }
      find_thread(info, si.si_pid, pl.pl_lwpid);

      if (si.si_status == SIGTRAP &&
          (pl.pl_flags &
           (PL_FLAG_BORN | PL_FLAG_EXITED | PL_FLAG_SCE | PL_FLAG_SCX)) != 0) {
        if (pl.pl_flags & PL_FLAG_BORN) {
          /* do nothing */
        } else if (pl.pl_flags & PL_FLAG_EXITED) {
          free_thread(info->curthread);
          info->curthread = NULL;
        } else if (pl.pl_flags & PL_FLAG_SCE) {
          enter_syscall(info, info->curthread, &pl);
        } else if (pl.pl_flags & PL_FLAG_SCX) {
          exit_syscall(info, &pl);
        }
        pending_signal = 0;
      } else if (pl.pl_flags & PL_FLAG_CHILD) {
        pending_signal = 0;
      } else {
        pending_signal = si.si_status;
      }
      ptrace(PT_SYSCALL, si.si_pid, (caddr_t)1, pending_signal);
      break;
    case CLD_STOPPED:
      errx(1, "waitid reported CLD_STOPPED");
    case CLD_CONTINUED:
      break;
    }
  }
}
