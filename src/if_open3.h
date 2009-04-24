/* vi:set ts=8 sts=4 sw=4:
 *
 * VIM - Vi IMproved	by Bram Moolenaar
 *			Pipe communication with child processes
 *			by Norbert Buchmuller
 *
 * Do ":help uganda"  in Vim to read copying and usage conditions.
 * Do ":help credits" in Vim to see a list of people who contributed.
 */

/*
 * Implements VimScript commands to handle child processes and
 * communicate with them using pipes, similarly to Perl's IPC::Open3.
 *
 * See ":help open3" for explanation.
 */

#ifndef __if_open3_h__
#define __if_open3_h__

#include "auto/config.h"

/* TODO: review how portable these includes are */
#include <stdio.h>
#include <unistd.h>

#if defined(UNIX)
# include <sys/types.h>         /* pid_t */
#else
# if defined (WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
# endif
#endif


#define OPEN3_SUCCESS		0
#define OPEN3_FAILURE		-1


/* Number of child processes allowed. */
#define MAX_CHILD_PROCESSES	10

/* Number of file handles supported. */
#define MAX_FILEHANDLES		(3 * MAX_CHILD_PROCESSES)


typedef struct {
} open3_iobuffer_T;

typedef struct {
    int fd;
    open3_iobuffer_T buf;
} open3_filehandle_T;

typedef struct {
#if defined(UNIX)
    pid_t           pid;	/* process id, 0 if unused */
#else
# if defined(WIN32)
    DWORD           pid;	/* process id, 0 if unused */
    HANDLE          hProc;
# endif
#endif
    char *cmd;	    /* given by the user */
    char *real_cmd; /* expanded using $PATH, etc. */
    size_t args_len;
    char **args;
    size_t env_len;
    char **env;
    int use_pty;
    open3_filehandle_T to_stdin;
    open3_filehandle_T from_stdout;
    open3_filehandle_T from_stderr;
} open3_proc_T;

extern open3_proc_T open3_proc[MAX_CHILD_PROCESSES];
extern open3_filehandle_T open3_fh[MAX_FILEHANDLES];

void		open3_perform_io __ARGS((int));
int		open3_spawn_child __ARGS((const char *,
		    size_t, const char **, size_t, const char **, int));

#endif /* __if_open3_h__ */
