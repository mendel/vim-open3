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

#include "vim.h"

#include "if_open3.h"

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

static int	spawn_child __ARGS((open3_proc_T *));
static open3_proc_T*	init_proc_handle __ARGS((
    int, const char*, size_t, const char**, size_t, const char**, int));
static void	wait_child __ARGS((int));
static int	find_free_proc_handle __ARGS(());
static void	free_proc_handle __ARGS((int));


open3_proc_T open3_proc[MAX_CHILD_PROCESSES];

/*
 * Called when I/O is possible on fd.
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

//open3_eval_read(fh, )




/*
 * Creates the pipes and starts the child process.
 *
 * Returns the process handle.
 */
    int
open3_spawn_child(cmd, args_len, args, env_len, env, use_pty)
    const char *cmd;
    size_t args_len;
    const char **args;
    size_t env_len;
    const char **env;
    int use_pty;
{
    int proc_idx;
    open3_proc_T *proc;

    /* Find a free process handle slot. */
    proc_idx = find_free_proc_handle();
    if (proc_idx < 0)
    {
	(void)EMSG(_("EXXX: Ran out of free child process slots"));
	goto error;
    }

    /* Fill in the file handle struct. */
    proc = init_proc_handle(proc_idx, cmd, args_len, args, env_len, env, use_pty);
    if (!proc)
    {
	goto error;
    }

    /* Create the child process with pipes attached to it. */
    if (!spawn_child(proc))
    {
	goto error;
    }

end:
    return proc_idx;

error:
    /* Free the process handle data and mark the slot free. */
    free_proc_handle(proc_idx);

    return -1;
} /* open3_spawn_child */


#ifdef UNIX

/*
 * Creates the pipes and starts the child process. (UNIX implementation)
 *
 * Returns: true on success, false on error.
 */
    static int
spawn_child(proc)
    open3_proc_T *proc;
{
    int stdin_pipe[2] = {-1, -1};
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};

    /* Set up the SIGCHLD handler. */
    install_sigchld_handler(void)

    //FIXME implement pty stuff

    /* Create the pipes. */
    if ((pipe(stdin_pipe) < 0) || (pipe(stdout_pipe) < 0)
        || (pipe(stderr_pipe) < 0))
    {
	PERROR(_("EXXX: Could not create pipes"));
	goto error;
    }

    /* Create the child process. */
    switch (proc->pid = fork())
    {
    case -1:				/* error */
	PERROR(_("EXXX: Could not fork child process"));
	goto error;
    case 0:				/* child */
	if (dup2(stdin_pipe[0], STDIN_FILENO) == -1)
	{
	    PERROR(_("EXXX: Could not duplicate file descriptor"));
	    goto child_error;
	}
	if (dup2(stdin_pipe[1], STDOUT_FILENO) == -1)
	{
	    PERROR(_("EXXX: Could not duplicate file descriptor"));
	    goto child_error;
	}
	if (dup2(stdin_pipe[1], STDERR_FILENO) == -1)
	{
	    PERROR(_("EXXX: Could not duplicate file descriptor"));
	    goto child_error;
	}

	/* Close unused ends of the pipes. */
	(void)close(stdin_pipe[1]);
	(void)close(stdout_pipe[0]);
	(void)close(stderr_pipe[0]);

	/* Run the command. */
	if (execve(proc->real_cmd, proc->args, proc->env) == -1)
	{
	    PERROR(_("EXXX: Could not execute command"));
	}
child_error:
	exit(127);
	/* NOTREACHED */
    default:				/* parent */
	/* Save the file descriptors. */
	proc->to_stdin.fd = stdin_pipe[1];
	proc->from_stdout.fd = stdout_pipe[0];
	proc->from_stderr.fd = stderr_pipe[0];

	/* Close unused ends of the pipes. */
	(void)close(stdin_pipe[0]);
	stdin_pipe[0] = -1;
	(void)close(stdout_pipe[1]);
	stdout_pipe[1] = -1;
	(void)close(stderr_pipe[1]);
	stderr_pipe[1] = -1;
    }

end:
    return 1;

error:
    /* Close pipes */
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

    return 0;
} /* spawn_child */


#else /* UNIX */


/*
 * Creates the pipes and starts the child process. (WIN32 implementation)
 *
 * Returns: true on success, false on error.
 */
    static int
spawn_child(proc)
    open3_proc_T *proc;
{
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

    //FIXME implement pty stuff

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    /* Create the pipes. */
    if (!(pipe_stdin = CreatePipe(&stdin_rd, &stdin_wr, &sa, 0))
	|| !(pipe_stdout = CreatePipe(&stdout_rd, &stdout_wr, &sa, 0))
	|| !(pipe_stderr = CreatePipe(&stderr_rd, &stderr_wr, &sa, 0)))
    {
	PERROR(_("EXXX: Could not create pipes"));
	goto error;
    }

    GetStartupInfo(&si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  /* Hide child application window */
    si.hStdInput  = stdin_rd;
    si.hStdOutput = stdout_wr;
    si.hStdError  = stderr_wr;

    /* Create the child process. */
    created = CreateProcess(NULL, cmd, NULL, NULL, TRUE, CREATE_NEW_CONSOLE,
							NULL, NULL, &si, &pi);
    if (!created)
    {
	PERROR(_("EXXX: Could not execute child process"));
	goto error;
    }
    proc->pid = pi.dwProcessId;
    proc->hProc = pi.hProcess;
    CloseHandle(pi.hThread);

    /* TODO - tidy up after failure to create files on pipe handles. */
    if (((proc->to_stdin.fd = _open_osfhandle((OPEN_OH_ARGTYPE)stdin_wr,
						      _O_TEXT|_O_APPEND)) < 0))
    {
	PERROR(_("EXXX: Could not open pipes to child process"));
	goto error;
    }
    if (((proc->from_stdout.fd = _open_osfhandle((OPEN_OH_ARGTYPE)stdout_rd,
						      _O_TEXT|_O_RDONLY)) < 0))
    {
	PERROR(_("EXXX: Could not open pipes to child process"));
	goto error;
    }
    if (((proc->from_stderr.fd = _open_osfhandle((OPEN_OH_ARGTYPE)stderr_rd,
						      _O_TEXT|_O_RDONLY)) < 0))
    {
	PERROR(_("EXXX: Could not open pipes to child process"));
	goto error;
    }

    /* Close handles for file descriptors inherited by the cscope process */
    CloseHandle(stdin_rd);
    CloseHandle(stdout_wr);
    CloseHandle(stderr_wr);

end:
    return 1;

error:
    /* Close the handles */
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

    return 0;
} /* spawn_child */

#endif /* UNIX */


/*
 * Initializes the open3_proc_T structure.
 *
 * Returns: the pointer to the open3_proc_T struct on success, NULL on error.
 */
    static open3_proc_T*
init_proc_handle(proc_idx, cmd, args_len, args, env_len, env, use_pty)
    int proc_idx;
    const char *cmd;
    size_t args_len;
    const char **args;
    size_t env_len;
    const char **env;
    int use_pty;
{
    open3_proc_T *proc = &open3_proc[proc_idx];

    vim_memset(proc, 0, sizeof(*proc));

    proc->cmd = strdup(cmd);

    /* Expand environment variables in the command line. */
    if (!(proc->real_cmd = (char *)alloc(MAXPATHL + 1)))
    {
	goto error;
    }
    expand_env((char_u *)proc->real_cmd, (char_u *)proc->cmd, MAXPATHL);
    if (proc->cmd == proc->real_cmd)
    {
	goto error;
    }

    /* Copy arguments, and prepend command name and append a NULL. */
    if (!(proc->args = (char **)alloc((args_len + 2) * sizeof(char *))))
    {
	goto error;
    }
    vim_memset(proc->args, 0, (args_len + 2) * sizeof(char *));
    proc->args[0] = strdup(proc->cmd);
    {
	int i;

	for (i = 1; i <= args_len; ++i)
	{
	    if (!(proc->args[i] = strdup(args[i])))
	    {
		goto error;
	    }
	}
    }
    proc->args[args_len + 1] = NULL;

    /* Copy envvars, and append a NULL. */
    if (!(proc->env = (char **)alloc((env_len + 1) * sizeof(char *))))
    {
	goto error;
    }
    vim_memset(proc->env, 0, (env_len + 1) * sizeof(char *));
    {
	int i;

	for (i = 0; i < env_len; ++i)
	{
	    if (!(proc->env[i] = strdup(env[i])))
	    {
		goto error;
	    }
	}
    }
    proc->env[env_len] = NULL;

end:
    return proc;

error:
    free_proc_handle(proc_idx);

    return NULL;
} /* init_proc_handle */


/*
 * Kills and waits for the child process.
 */
    static void
wait_child(idx)
    int idx;
{
    proc = &open3_proc[idx];

    if (!proc->pid)
    {
	return;	    /* already reaped */
    }

#if defined(UNIX)
    /* First ask it politely to terminate. */
    kill(proc->pid, SIGTERM);

    {
	int waitpid_errno;
	int pstat;
	pid_t pid;

# if defined(HAVE_SIGACTION)
	struct sigaction sa, old;

	/* Use sigaction() to limit the waiting time to two seconds. */
	(void)sigemptyset(&sa.sa_mask);
	sa.sa_handler = &sigalarm_handler;
	sa.sa_flags = SA_NODEFER;
	(void)sigaction(SIGALRM, &sa, &old);
	(void)alarm(2); /* 2 sec timeout */

	/* Block until the child process exits or until timer expires */
	pid = waitpid(proc->pid, &pstat, 0);
	waitpid_errno = errno;

	/* cancel pending alarm if still there and restore signal */
	(void)alarm(0);
	(void)sigaction(SIGALRM, &old, NULL);
# else
	int waited;

	/* Can't use sigaction(), loop for two seconds.  First yield the CPU
	 * to give the child process a chance to exit quickly. */
	(void)sleep(0);
	for (waited = 0; waited < 40; ++waited)
	{
	    pid = waitpid(proc->pid, &pstat, WNOHANG);
	    waitpid_errno = errno;
	    if (pid != 0)
		break;  /* break unless the process is still running */
	    mch_delay(50L, FALSE); /* sleep 50 ms */
	}
# endif
	/*
	 * If the child process is still running: kill it.
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
		 * When using 'vim -g', vim is forked and the child process is
		 * no longer a child process but a sibling.  So waitpid()
		 * fails with errno being ECHILD (No child processes).
		 */
		int waited;

		(void)sleep(0);
		for (waited = 0; waited < 40; ++waited)
		{
		    /* Check whether the child process is still alive */
		    if (kill(proc->pid, 0) != 0)
		    {
			alive = FALSE; /* the child process no longer exists */
			break;
		    }
		    mch_delay(50L, FALSE); /* sleep 50ms */
		}
	    }
	    if (alive)
# endif
	    {
		(void)kill(proc->pid, SIGKILL);
		(void)waitpid(proc->pid, &pstat, 0);
	    }
	}
    }
#else  /* UNIX */
    if (proc->hProc != NULL)
    {
	/* Give the child process a chance to exit normally */
	if (WaitForSingleObject(proc->hProc, 1000) == WAIT_TIMEOUT)
	    TerminateProcess(proc->hProc, 0);
	CloseHandle(proc->hProc);
    }
#endif	/* UNIX */

    free_proc_handle(idx);
} /* wait_child */


#if defined(UNIX) && defined(SIGALRM)
/*
 * Used to catch and ignore SIGALRM.
 */
/* ARGSUSED */
    static RETSIGTYPE
sigalarm_handler SIGDEFARG(sigarg)
{
    /* do nothing */
    SIGRETURN;
}
#endif


#if defined(UNIX)

/* Addess of the previous SIGCHLD handler. */
static sighandler_t old_sigchld_handler;


/*
 * SIGCHLD handler. Calls the next handler.
 */
    static void
sigchld_handler(signum)
    int signum;
{
    if (old_sigchld_handler)
    {
	old_sigchld_handler(signum);
    }

    SIGRETURN;
}


/*
 * Installs the above SIGCHLD handler.
 */
    static void
install_sigchld_handler(void)
{
    if (old_sigchld_handler)
    {
	return;	    /* already installed */
    }

#if defined(HAVE_SIGACTION)
    struct sigaction sa, old_sa;

    (void)sigemptyset(&sa.sa_mask);
    sa.sa_handler = &sigchld_handler;
    sa.sa_flags = SA_NODEFER;
    if (!sigaction(SIGCHLD, &sa, &old_sa)) {
	(void)EMSG(_("EXXX: Cannot install SIGCHLD handler"));
    }
    old_sigchld_handler = old_sa.sa_handler;
#else
    old_sigchld_handler = signal(SIGCHLD, &sigchld_handler);
    if (old_sigchld_handler == SIG_ERR) {
	(void)EMSG(_("EXXX: Cannot install SIGCHLD handler"));
    }
#endif

    if (old_sigchld_handler == SIG_IGN || old_sigchld_handler == SIG_DFL)
    {
	old_sigchld_handler = NULL;
    }
}

#endif	/* UNIX */


/*
 * Finds the next unused process slot in open3_proc.
 *
 * Returns the index of the first free slot.
 */
    static int
find_free_proc_handle()
{
    int i;

    for (i = 0; i < MAX_CHILD_PROCESSES; ++i)
    {
	if (!open3_proc[i].pid)
	{
	    return i;
	}
    }

    return -1;
}

/*
 * Frees and zeroes all fields of the process slot.
 */
    static void
free_proc_handle(idx)
    int idx;
{
    int i;
    open3_proc_T *proc;

    proc = &open3_proc[idx];

    if (!proc->pid)
    {
	return;	    /* already freed */
    }

    proc->pid = 0;

    vim_free(proc->cmd);
    vim_free(proc->real_cmd);

    for (i = 0; i < proc->args_len; ++i)
    {
	if (proc->args[i])
	{
	    vim_free(proc->args[i]);
	    proc->args[i] = NULL;
	}
    }
    proc->args_len = 0;

    for (i = 0; i < proc->env_len; ++i)
    {
	if (proc->env[i])
	{
	    vim_free(proc->env[i]);
	    proc->env[i] = NULL;
	}
    }
    proc->env_len = 0;

    proc->use_pty = 0;

    if (proc->to_stdin.fd != -1)
    {
#if defined(UNIX)
	(void)close(proc->to_stdin.fd);
#else	/* UNIX */
	CloseHandle(proc->to_stdin.fd);
#endif	/* UNIX */
	proc->to_stdin.fd = -1;
    }
    if (proc->from_stdout.fd != -1)
    {
#if defined(UNIX)
	(void)close(proc->from_stdout.fd);
#else	/* UNIX */
	CloseHandle(proc->from_stdout.fd);
#endif	/* UNIX */
	proc->from_stdout.fd = -1;
    }
    if (proc->from_stderr.fd != -1)
    {
#if defined(UNIX)
	(void)close(proc->from_stderr.fd);
#else	/* UNIX */
	CloseHandle(proc->from_stderr.fd);
#endif	/* UNIX */
	proc->from_stderr.fd = -1;
    }

    //FIXME free iobufs
}
