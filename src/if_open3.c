/* vi:set ts=8 sts=4 sw=4:
 *
 * VIM - Vi IMproved	by Bram Moolenaar
 *			Pipe communication with child processes
 *			by Norbert Buchmuller
 *			Based on code from if_cscope.c
 *			(by Andy Kahn <kahn@zk3.dec.com> and
 *			Sergey Khorev <sergey.khorev@gmail.com>)
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

#include "if_open3.h"

#include "vim.h"

/* TODO: review how portable these includes are */
#include <stdio.h>
#include <unistd.h>

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined(UNIX)
# include <sys/wait.h>
#else
# include "vimio.h"
#endif



struct open3_filehandle open3_filehandles[MAX_FILEHANDLES];


/*
 * open3_perform_io -- Called when the I/O is possible on fd.
 *
 * This function is called from the I/O reactor (select()/poll()
 * on console, or the corresponding event loop of the GUI) when
 * I/O is possible (will not block) on the file descriptor.
 */
    void
open3_perform_io(fd)
    int fd;
{
    //FIXME implement this
}

open3_eval_read(fh, )







    static int
open3_spawn_child(cmd, args_len, args, env_len, env, use_pty)
    const char *cmd;
    size_t args_len;
    const char **args;
    size_t env_len;
    const char **env;
    int use_pty;
{
    int fh_idx;
    open3_filehandle_T *fh;
#ifdef UNIX
    int stdin_pipe[2] = {-1, -1};
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
#else
    /* WIN32 */
    int		fd;
    SECURITY_ATTRIBUTES sa;
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    BOOL	pipe_stdin = FALSE, pipe_stdout = FALSE, pipe_stderr = FALSE;
    HANDLE	stdin_rd, stdout_rd, stderr_rd;
    HANDLE	stdin_wr, stdout_wr, stderr_wr;
    BOOL	created;
# ifdef __BORLANDC__
#  define OPEN_OH_ARGTYPE long
# else
#  if (_MSC_VER >= 1300)
#   define OPEN_OH_ARGTYPE intptr_t
#  else
#   define OPEN_OH_ARGTYPE long
#  endif
# endif
#endif	/* !UNIX */

    /* Find a free filehandle slot. */
    fh_idx = find_free_filehandle();
    if (fh_idx < 0)
    {
	(void)EMSG(_("EXXX: Ran out of free filehandles"));
	goto error;
    }
    fh = &open3_fh[fh_idx];

    /* Fill in the file handle struct. */
    {
	int i;

	fh->cmd = strdup(cmd);

	/* Expand environment variables in the command line. */
	if (!(fh->real_cmd = (char *)alloc(MAXPATHL + 1)))
	{
	    goto error;
	}
	expand_env((char_u *)fh->real_cmd, (char_u *)fh->cmd, MAXPATHL);
	if (fh->cmd == fh->real_cmd)
	{
	    goto error;
	}

	if (!(fh->args = (char **)alloc((args_len + 1) * sizeof(char *))))
	{
	    goto error;
	}
	for (i = 0; i < args_len; ++i)
	{
	    if (!(fh->args[i] = strdup(args[i])))
	    {
		goto error;
	    }
	}
	fh->args[args_len] = NULL;

	if (!(fh->env = (char **)alloc((env_len + 1) * sizeof(char *))))
	{
	    goto error;
	}
	for (i = 0; i < env_len; ++i)
	{
	    if (!(fh->env[i] = strdup(env[i])))
	    {
		goto error;
	    }
	}
	fh->env[env_len] = NULL;
    }

    //FIXME PERROR() vs. EMSG()
    //FIXME (void) prefixes to function calls
    //FIXME exit path on errors (deallocate memory, set fh->pid to 0)

    //FIXME implement pty stuff

    /* Create the pipes. */
#if defined(UNIX)
    if ((pipe(stdin_pipe) < 0) || (pipe(stdout_pipe) < 0)
        || (pipe(stderr_pipe) < 0))
    {
	PERROR(_("open3_spawn_child: pipe failed"));
	(void)EMSG(_("EXXX: Could not create pipes"));
	goto error;
    }
#else
    /* WIN32 */
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!(pipe_stdin = CreatePipe(&stdin_rd, &stdin_wr, &sa, 0))
	|| !(pipe_stdout = CreatePipe(&stdout_rd, &stdout_wr, &sa, 0))
	|| !(pipe_stderr = CreatePipe(&stderr_rd, &stderr_wr, &sa, 0)))
    {
	PERROR(_("open3_spawn_child: pipe failed"));
	(void)EMSG(_("EXXX: Could not create pipes"));
	goto error;
    }
#endif	/* !UNIX */

    /* Create the child process. */
#if defined(UNIX)
    switch (fh->pid = fork())
    {
    case -1:				/* error */
	PERROR(_("open3_spawn_child: fork failed"));
	(void)EMSG(_("EXXX: Could not fork for child process"));
	goto error;
    case 0:				/* child */
	if (dup2(stdin_pipe[0], STDIN_FILENO) == -1)
	{
	    PERROR(_("open3_spawn_child: dup2 failed"));
	    (void)EMSG(_("EXXX: Could not redirect stdin"));
	    goto child_error;
	}
	if (dup2(stdin_pipe[1], STDOUT_FILENO) == -1)
	{
	    PERROR(_("open3_spawn_child: dup2 failed"));
	    (void)EMSG(_("EXXX: Could not redirect stdout"));
	    goto child_error;
	}
	if (dup2(stdin_pipe[1], STDERR_FILENO) == -1)
	{
	    PERROR(_("open3_spawn_child: dup2 failed"));
	    (void)EMSG(_("EXXX: Could not redirect stderr"));
	    goto child_error;
	}

	/* Close unused ends of the pipes. */
	(void)close(stdin_pipe[1]);
	(void)close(stdout_pipe[0]);
	(void)close(stderr_pipe[0]);

	/* Run the command. */
	if (execl(fh->real_cmd, fh->args, NULL) == -1)
	{
	    PERROR(_("open3_spawn_child: execl failed"));
	    (void)EMSG(_("EXXX: Could not execute command"));
	}
child_error:
	exit(127);
	/* NOTREACHED */
    default:				/* parent */
	 /* Save the file descriptors. */
	fh->to_stdin = stdin_pipe[1];
	fh->from_stdout = stdout_pipe[0];
	fh->from_stderr = stderr_pipe[0];

	/* Close unused ends of the pipes. */
	(void)close(stdin_pipe[0]);
	stdin_pipe[0] = -1;
	(void)close(stdout_pipe[1]);
	stdout_pipe[1] = -1;
	(void)close(stderr_pipe[1]);
	stderr_pipe[1] = -1;
    }
#else
    /* WIN32 */
    GetStartupInfo(&si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  /* Hide child application window */
    si.hStdInput  = stdin_rd;
    si.hStdOutput = stdout_wr;
    si.hStdError  = stderr_wr;
    created = CreateProcess(NULL, cmd, NULL, NULL, TRUE, CREATE_NEW_CONSOLE,
							NULL, NULL, &si, &pi);
    if (!created)
    {
	PERROR(_("open3_spawn_child: exec failed"));
	(void)EMSG(_("EXXX: Could not spawn child process"));
	goto error;
    }
    csinfo[i].pid = pi.dwProcessId;
    csinfo[i].hProc = pi.hProcess;
    CloseHandle(pi.hThread);

    /* TODO - tidy up after failure to create files on pipe handles. */
    if (((fh->to_stdin = _open_osfhandle((OPEN_OH_ARGTYPE)stdin_wr,
						      _O_TEXT|_O_APPEND)) < 0))
    {
	PERROR(_("open3_spawn_child: _open_osfhandle for child stdin failed"));
	(void)EMSG(_("EXXX: Could not open pipes to child process"));
	goto error;
    }
    if (((fh->from_stdout = _open_osfhandle((OPEN_OH_ARGTYPE)stdout_rd,
						      _O_TEXT|_O_RDONLY)) < 0))
    {
	PERROR(_("open3_spawn_child: _open_osfhandle for child stdout failed"));
	(void)EMSG(_("EXXX: Could not open pipes to child process"));
	goto error;
    }
    if (((fh->from_stderr = _open_osfhandle((OPEN_OH_ARGTYPE)stderr_rd,
						      _O_TEXT|_O_RDONLY)) < 0))
    {
	PERROR(_("open3_spawn_child: _open_osfhandle for child stderr failed"));
	(void)EMSG(_("EXXX: Could not open pipes to child process"));
	goto error;
    }

    /* Close handles for file descriptors inherited by the cscope process */
    CloseHandle(stdin_rd);
    CloseHandle(stdout_wr);
    CloseHandle(stderr_wr);
#endif /* !UNIX */

end:
    return fh_idx;

error:
    /* First close pipes */
#if defined(UNIX)
    if (stdin_pipe[0] >= 0) {
	(void)close(stdin_pipe[0]);
    }
    if (stdin_pipe[1] >= 0) {
	(void)close(stdin_pipe[1]);
    }
    if (stdout_pipe[0] >= 0) {
	(void)close(stdout_pipe[0]);
    }
    if (stdout_pipe[1] >= 0) {
	(void)close(stdout_pipe[1]);
    }
    if (stderr_pipe[0] >= 0) {
	(void)close(stderr_pipe[0]);
    }
    if (stderr_pipe[1] >= 0) {
	(void)close(stderr_pipe[1]);
    }
#else
/* WIN32 */
    if (pipe_stdin)
    {
	CloseHandle(stdin_rd);
	CloseHandle(stdin_wr);
    }
    if (pipe_stdout)
    {
	CloseHandle(stdout_rd);
	CloseHandle(stdout_wr);
    }
    if (pipe_stderr)
    {
	CloseHandle(stderr_rd);
	CloseHandle(stderr_wr);
    }
#endif	/* !UNIX */

    /* Then mark the filehandle slot as free. */
    free_filehandle(fh_idx);

    return -1;
} /* open3_spawn_child */

/*
 * PRIVATE: cs_release_csp
 *
 * Does the actual free'ing for the cs ptr with an optional flag of whether
 * or not to free the filename.  Called by cs_kill and cs_reset.
 */
    static void
cs_release_csp(i, freefnpp)
    int i;
    int freefnpp;
{
    /*
     * Trying to exit normally (not sure whether it is fit to UNIX cscope
     */
    if (csinfo[i].to_fp != NULL)
    {
	(void)fputs("q\n", csinfo[i].to_fp);
	(void)fflush(csinfo[i].to_fp);
    }
#if defined(UNIX)
    {
	int waitpid_errno;
	int pstat;
	pid_t pid;

# if defined(HAVE_SIGACTION)
	struct sigaction sa, old;

	/* Use sigaction() to limit the waiting time to two seconds. */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sig_handler;
	sa.sa_flags = SA_NODEFER;
	sigaction(SIGALRM, &sa, &old);
	alarm(2); /* 2 sec timeout */

	/* Block until cscope exits or until timer expires */
	pid = waitpid(csinfo[i].pid, &pstat, 0);
	waitpid_errno = errno;

	/* cancel pending alarm if still there and restore signal */
	alarm(0);
	sigaction(SIGALRM, &old, NULL);
# else
	int waited;

	/* Can't use sigaction(), loop for two seconds.  First yield the CPU
	 * to give cscope a chance to exit quickly. */
	sleep(0);
	for (waited = 0; waited < 40; ++waited)
	{
	    pid = waitpid(csinfo[i].pid, &pstat, WNOHANG);
	    waitpid_errno = errno;
	    if (pid != 0)
		break;  /* break unless the process is still running */
	    mch_delay(50L, FALSE); /* sleep 50 ms */
	}
# endif
	/*
	 * If the cscope process is still running: kill it.
	 * Safety check: If the PID would be zero here, the entire X session
	 * would be killed.  -1 and 1 are dangerous as well.
	 */
	if (pid < 0 && csinfo[i].pid > 1)
	{
# ifdef ECHILD
	    int alive = TRUE;

	    if (waitpid_errno == ECHILD)
	    {
		/*
		 * When using 'vim -g', vim is forked and cscope process is
		 * no longer a child process but a sibling.  So waitpid()
		 * fails with errno being ECHILD (No child processes).
		 * Don't send SIGKILL to cscope immediately but wait
		 * (polling) for it to exit normally as result of sending
		 * the "q" command, hence giving it a chance to clean up
		 * its temporary files.
		 */
		int waited;

		sleep(0);
		for (waited = 0; waited < 40; ++waited)
		{
		    /* Check whether cscope process is still alive */
		    if (kill(csinfo[i].pid, 0) != 0)
		    {
			alive = FALSE; /* cscope process no longer exists */
			break;
		    }
		    mch_delay(50L, FALSE); /* sleep 50ms */
		}
	    }
	    if (alive)
# endif
	    {
		kill(csinfo[i].pid, SIGKILL);
		(void)waitpid(csinfo[i].pid, &pstat, 0);
	    }
	}
    }
#else  /* !UNIX */
    if (csinfo[i].hProc != NULL)
    {
	/* Give cscope a chance to exit normally */
	if (WaitForSingleObject(csinfo[i].hProc, 1000) == WAIT_TIMEOUT)
	    TerminateProcess(csinfo[i].hProc, 0);
	CloseHandle(csinfo[i].hProc);
    }
#endif

    if (csinfo[i].fr_fp != NULL)
	(void)fclose(csinfo[i].fr_fp);
    if (csinfo[i].to_fp != NULL)
	(void)fclose(csinfo[i].to_fp);

    if (freefnpp)
    {
	vim_free(csinfo[i].fname);
	vim_free(csinfo[i].ppath);
	vim_free(csinfo[i].flags);
    }

    clear_csinfo(i);
} /* cs_release_csp */

/*
 * find_free_filehandle -- Finds the next unused slot in open3_fh.
 *
 * Returns the index of the first free slot.
 */
    static int
find_free_filehandle()
{
    int i;

    for (i = 0; i < MAX_FILEHANDLES; ++i)
    {
	if (!open3_fh[i].pid)
	{
	    return i;
	}
    }

    return -1;
}

/*
 * free_filehandle -- Clears all fields of filehandle (and mark it as free).
 */
    static void
free_filehandle(idx)
    int idx;
{
    int i;
    open3_filehandle_T *fh;

    fh = &open3_fh[idx];

    if (!fh->pid)
    {
	return;	    /* already freed */
    }

    fh->pid = 0;

    vim_free(fh->cmd);
    vim_free(fh->real_cmd);

    for (i = 0; i < fh->args_len; ++i)
    {
	if (fh->args[i])
	{
	    vim_free(fh->args[i]);
	    fh->args[i] = NULL;
	}
    }
    fh->args_len = 0;

    for (i = 0; i < fh->env_len; ++i)
    {
	if (fh->env[i])
	{
	    vim_free(fh->env[i]);
	    fh->env[i] = NULL;
	}
    }
    fh->env_len = 0;

    fh->use_pty = 0;

    //FIXME free file descriptors and iobufs
}
