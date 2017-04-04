/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 * Cojan Eugen Nicolae, 332CA
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1
#define APPEND		100
#define TRUNC		101


/**
 * Do redirect for filedescriptor with io type.
 */
static void do_redirect(int filedes, const char *filename, int io_type,
	int is_cd)
{
	int rc = 1;
	int fd;
	/* If it's a filedescriptor for STDIN */
	if (filedes == STDIN_FILENO) {
		fd = open(filename, O_RDONLY);
		DIE(fd < 0, "Error opening file for stdin");
	}
	/* If it's a filedescriptor for STDOUT or STDERR */
	if (filedes == STDERR_FILENO || filedes == STDOUT_FILENO) {
		/* io_type for the type of open, Append or Trunc */
		if (io_type == TRUNC)
			fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		else if (io_type == APPEND)
			fd = open(filename, O_WRONLY |
				O_CREAT | O_APPEND, 0644);

		DIE(fd < 0, "Error opening filedescriptor");
	}
	/* Treat the cd case */
	if (is_cd == 0)
		rc = dup2(fd, filedes);
	DIE(rc < 0, "Error dup2");
	close(fd);
}

/**
 * Solve redirects
 */
static void solve_redirects(simple_command_t *s)
{
	word_t *in = s->in;
	word_t *out = s->out;
	word_t *err = s->err;
	int io_flags = s->io_flags;
	char *filein, *fileout, *fileerr;
	int io_type_in, io_type_out, io_type_err;
	int is_cd;
	char *verb = get_word(s->verb);
	/* set the flag if we are dealing with a cd command */
	if (strcmp(verb, "cd") == 0)
		is_cd = 1;
	else
		is_cd = 0;
	/* if we have a STDIN redirect */
	if (in != NULL) {
		filein = get_word(in);
		io_type_in = -1;
		do_redirect(STDIN_FILENO, filein, io_type_in, is_cd);
		free(filein);
	}

	/* Treat cases if we have STDOUT and STDERR redirect */
	if (out != NULL && err != NULL) {
		fileout = get_word(out);
		fileerr = get_word(err);
		/* Get io flags for the the redirects */
		if (io_flags == IO_OUT_APPEND)
			io_type_out = APPEND;
		else
			io_type_out = TRUNC;
		if (io_flags == IO_ERR_APPEND)
			io_type_err = APPEND;
		else
			io_type_err = TRUNC;
		/* if STDERR and STDOUT are the same file */
		if (strcmp(fileout, fileerr) == 0) {
			do_redirect(STDERR_FILENO, fileerr, io_type_err, is_cd);
			do_redirect(STDOUT_FILENO, fileout, APPEND, is_cd);
		} else {
			do_redirect(STDOUT_FILENO, fileout, io_type_out, is_cd);
			do_redirect(STDERR_FILENO, fileerr, io_type_err, is_cd);
		}

		free(fileout);
		free(fileerr);
		/* If we have a STDOUT redirect but not a STDERR redirect */
	} else if (out == NULL && err != NULL) {

		fileerr = get_word(err);

		if (io_flags == IO_ERR_APPEND)
			io_type_err = APPEND;
		else
			io_type_err = TRUNC;

		do_redirect(STDERR_FILENO, fileerr, io_type_err, is_cd);
		free(fileerr);
		/* If we have a STDERR redirect but not a STDOUT redirect */
	} else if (out != NULL && err == NULL) {

		fileout = get_word(out);

		if (io_flags == IO_OUT_APPEND)
			io_type_out = APPEND;
		else
			io_type_out = TRUNC;

		do_redirect(STDOUT_FILENO, fileout, io_type_out, is_cd);
		free(fileout);
	}
	free(verb);
}

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	int ret;
	/* execute cd */

	if (dir == NULL)
		return -1;
	char *path = get_word(dir);

	ret = chdir(path);
	free(path);
	return ret;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* execute exit/quit */

	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	int ret = 0;
	int status, argv_size;
	char *verb;
	pid_t pid, wait_ret;
	char *cmd;
	char **argv;

	/* sanity checks */
	if (s == NULL) {
		fprintf(stderr, "Command error\n");
		return -1;
	}
	/* if builtin command, execute the command */

	verb = get_word(s->verb);

	if (strcmp(verb, "exit") == 0 || strcmp(verb, "quit") == 0) {

		ret = shell_exit();
		free(verb);
		return ret;
	}

	if (strcmp(verb, "cd") == 0) {
		/* do redirects before doing cd */
		solve_redirects(s);
		ret = shell_cd(s->params);
		free(verb);
		return ret;
	}
	/* if variable assignment, execute the assignment and return
	 * the exit status
	 */
	free(verb);
	/* check if we have a next part */
	if (s->verb->next_part != NULL) {

		const char *variable = s->verb->string;
		/* and if that part is an equal */
		if (strcmp(s->verb->next_part->string, "=") == 0) {

			if (s->verb->next_part->next_part != NULL) {
				/* if we have de value also, set the variable */
				const char *value =
					s->verb->next_part->next_part->string;
				ret = setenv(variable, value, 1);

				if (ret < 0)
					fprintf(stderr, "setenv error\n");
				return ret;

			} else {

				fprintf(stderr, "Command error\n");
				return -1;
			}
		}
	}

	/* if external command:
	 *   1. fork new process
	 *     2c. perform redirections in child
	 *     3c. load executable in child
	 *   2. wait for child
	 *   3. return exit status
	 */

	pid = fork();


	switch (pid) {
	case -1:

		DIE(pid, "fork");
		break;
	case 0:
		/* if it's the child */

		/* solve redirects */
		solve_redirects(s);

		cmd = get_word(s->verb);
		argv = get_argv(s, &argv_size);
		/* execute the command */
		execvp(cmd, argv);

		/* if this point is reached then there is a problem */
		fprintf(stderr, "Execution failed for '%s'\n", cmd);
		free(cmd);

		int i;

		for (i = 0; i < argv_size; i++)
			free(argv[i]);

		free(argv);

		exit(EXIT_FAILURE);

		break;
	default:
		/* if it's the parent, wait for child*/
		wait_ret = waitpid(pid, &status, 0);
		DIE(wait_ret < 0, "waitpid");

		if (WIFEXITED(status))
			ret = WEXITSTATUS(status);

		break;
	}

	return ret;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* execute cmd1 and cmd2 simultaneously */
	int ret;
	int status;
	pid_t pid, wait_ret;


	pid = fork();


	switch (pid) {
	case -1:

		DIE(pid, "fork");
		break;
	case 0: /* if it's the child */
		/* do the command */
		ret = parse_command(cmd1, level+1, father);
		exit(ret);

		break;
	default: /* if it's the parent */

		/* do the other command and wait for child after */

		ret = parse_command(cmd2, level + 1, father);

		wait_ret = waitpid(pid, &status, 0);
		DIE(wait_ret < 0, "waitpid");

		break;
	}

	return ret;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */

static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* redirect the output of cmd1 to the input of cmd2 */

	int fd[2];
	int ret;
	pid_t pid, wait_ret;
	int status;
	int in, out;
	/* save the file descriptors for in and out */
	in = dup(STDIN_FILENO);
	out = dup(STDOUT_FILENO);

	ret = pipe(fd);
	DIE(ret < 0, "Error pipe");

	pid = fork();


	switch (pid) {
	case -1:

		DIE(pid, "fork");
		break;
	case 0: /* if it's the child */

		/* close reading for pipe */
		close(fd[0]);
		/* duplicate stdout in the pipe out */
		ret = dup2(fd[1], STDOUT_FILENO);
		DIE(ret < 0, "Error dup2");
		/* execute command */
		ret = parse_command(cmd1, level+1, father);

		/* close remaining file descriptor */
		close(fd[1]);
		exit(ret);

		break;
	default: /* if it's the parent */

		/* close output for pipe */
		close(fd[1]);
		/* duplicate stdin in the pipe in */
		ret = dup2(fd[0], STDIN_FILENO);
		DIE(ret < 0, "Error dup2");
		/* execute command */
		ret = parse_command(cmd2, level + 1, father);
		/* wait child */
		wait_ret = waitpid(pid, &status, 0);
		DIE(wait_ret < 0, "waitpid");
		/* restore file descriptors */
		dup2(in, STDIN_FILENO);
		dup2(out, STDOUT_FILENO);

		/* close remaining extra file descriptors */
		close(in);
		close(out);
		close(fd[0]);

		break;
	}

	return ret;
}


/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int ret = 0;
	/* sanity checks */
	if (c == NULL) {
		fprintf(stderr, "Command error\n");
		return -1;
	}
	if (c->op == OP_NONE) {
		/* execute a simple command */
		ret = parse_simple(c->scmd, level + 1, father);
		return ret;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* execute the commands one after the other */
		ret = parse_command(c->cmd1, level + 1, c);
		ret = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		/* execute the commands simultaneously */
		ret = do_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_NZERO:
		/* execute the second command only if the first one
		 * returns non zero
		 */
		ret = parse_command(c->cmd1, level + 1, c);
		if (ret != 0)
			ret = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		/* execute the second command only if the first one
		 * returns zero
		 */
		ret = parse_command(c->cmd1, level + 1, c);
		if (ret == 0)
			ret = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		/* redirect the output of the first command to the
		 * input of the second
		 */
		ret = do_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;

	default:
		return SHELL_EXIT;
	}

	return ret;
}
