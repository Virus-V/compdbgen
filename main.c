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

#include <sys/cdefs.h>
#include <sys/ptrace.h>

#include <err.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "compdbgen.h"

regex_t *regex_exec_cmds;
regex_t *regex_src_suffix;

extern void setup_and_wait(struct glbctx *, char **);
extern void mainloop(struct glbctx *);

static void usage(void) {
  fprintf(stderr, "%s\n", "usage: compdbgen command [args]");
  exit(1);
}

int main(int argc, char **argv) {
  struct glbctx *gctx;
  char *dbname;
  char **command;

  dbname = NULL;

  gctx = (struct glbctx *)calloc(1, sizeof(struct glbctx));
  if (gctx == NULL) {
    errx(1, "calloc() failed");
  }

  gctx->outfile = stderr;
  gctx->curthread = NULL;
  LIST_INIT(&gctx->proclist);

  dbname = "compile_commands.json";

  if ((gctx->outfile = fopen(dbname, "we")) == NULL) {
    err(1, "cannot open %s", dbname);
  }

  char *pattern_dump_hdr = "(cc|cc1|cpp|gcc|g\\+\\+|clang|clang\\+\\+)$";

  regex_exec_cmds = malloc(sizeof(regex_t));
  int ret =
      regcomp(regex_exec_cmds, pattern_dump_hdr, REG_EXTENDED | REG_NEWLINE);
  if (ret) {
    err(1, "cannot compile regex %s", pattern_dump_hdr);
  }

  regex_src_suffix = malloc(sizeof(regex_t));
  char *pattern_src_suffix = "\\.(c|cpp|S)$";
  ret =
      regcomp(regex_src_suffix, pattern_src_suffix, REG_EXTENDED | REG_NEWLINE);
  if (ret) {
    err(1, "cannot compile regex %s", pattern_src_suffix);
  }

  /* Start a command ourselves */
  command = argv + 1;
  setup_and_wait(gctx, command);
  signal(SIGINT, SIG_IGN);
  signal(SIGTERM, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);

  if (LIST_FIRST(&gctx->proclist)->abi == NULL) {
    kill(LIST_FIRST(&gctx->proclist)->pid, SIGKILL);
    ptrace(PTRACE_DETACH, LIST_FIRST(&gctx->proclist)->pid, NULL, 0);
    return (1);
  }
  ptrace(PTRACE_SYSCALL, LIST_FIRST(&gctx->proclist)->pid, NULL, 0);

  fputs("[\n", gctx->outfile);

  mainloop(gctx);

  fputs("\n]", gctx->outfile);

  fflush(gctx->outfile);

  return (0);
}