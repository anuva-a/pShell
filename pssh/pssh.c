#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <readline/readline.h>
#include "builtin.h"
#include "parse.h"
// #include "jobs.h"
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <ctype.h>

/*******************************************
 * Set to 1 to view the command line parse *
 *******************************************/
#define DEBUG_PARSE 0
#define READ_SIDE 0
#define WRITE_SIDE 1
#define MAX_JOBS 100

pid_t pssh;
typedef enum{
	STOPPED, 
	TERM, 
	BG, 
	FG
} JobStatus;
typedef struct{
    char* name;
    unsigned int npids;
	unsigned int pids_left;
    pid_t *pids;
    pid_t pgid;
    JobStatus status;
} Job;
Job jobs[MAX_JOBS];

void set_fg_pgid(pid_t pgid);
int addjob(Job* jobs, Parse* P, char* cmd_cpy);
int findjob(Job* jobs, pid_t pid);
void jobs_cmd(Job* jobs);
void fg(Job* jobs, Parse* P);
void bg(Job* jobs, Parse* P);
void kill_cmd(Job* jobs, Parse* P);


void print_banner ()
{
    printf ("                    ________   \n");
    printf ("_________________________  /_  \n");
    printf ("___  __ \\_  ___/_  ___/_  __ \\ \n");
    printf ("__  /_/ /(__  )_(__  )_  / / / \n");
    printf ("_  .___//____/ /____/ /_/ /_/  \n");
    printf ("/_/ Type 'exit' or ctrl+c to quit\n\n");
}


/* returns a string for building the prompt
 *
 * Note:
 *   If you modify this function to return a string on the heap,
 *   be sure to free() it later when appropirate!  */
static char* build_prompt ()
{
	char cwd[100000];
    getcwd(cwd, sizeof(cwd));
    return strcat(cwd, "$ ");
}


/* return true if command is found, either:
 *   - a valid fully qualified path was supplied to an existing file
 *   - the executable file was found in the system's PATH
 * false is returned otherwise */
static int command_found (const char* cmd)
{
    char* dir;
    char* tmp;
    char* PATH;
    char* state;
    char probe[PATH_MAX];

    int ret = 0;

    if (access (cmd, X_OK) == 0)
        return 1;

    PATH = strdup (getenv("PATH"));

    for (tmp=PATH; ; tmp=NULL) {
        dir = strtok_r (tmp, ":", &state);
        if (!dir)
            break;

        strncpy (probe, dir, PATH_MAX-1);
        strncat (probe, "/", PATH_MAX-1);
        strncat (probe, cmd, PATH_MAX-1);

        if (access (probe, X_OK) == 0) {
            ret = 1;
            break;
        }
    }

    free (PATH);
    return ret;
}

void safe_print (char* str){
	pid_t fg_pgid;
	fg_pgid = tcgetpgrp (STDOUT_FILENO);
	set_fg_pgid(getpgrp());
	printf("%s", str);
	set_fg_pgid(fg_pgid);
}

int addjob(Job* jobs, Parse* P, char* cmd_cpy){
    int i;
    for (i = 0; i < MAX_JOBS; i++){
        if (jobs[i].npids == 0){
            if (P->background){
                jobs[i].status = BG;
            } else {
                jobs[i].status = FG;
            }
            jobs[i].name = malloc(sizeof(cmd_cpy));
            strcpy(jobs[i].name, cmd_cpy);
            free(cmd_cpy);
            return i;
        }
    }
    return -1;
}

int findjob(Job* jobs, pid_t pid){
    int i,j;
    for (i = 0; i < MAX_JOBS; i++){
        for (j=0; j < jobs[i].npids; j++){
            if (jobs[i].pids[j] == pid){
                return i;
            }
        }
    }
    return -1;
}

void deletejob(Job* jobs, int jobnum){
	free(jobs[jobnum].name);
	free(jobs[jobnum].pids);
	jobs[jobnum].npids = 0;
	jobs[jobnum].pids_left = 0;
	jobs[jobnum].status = TERM;
}

void set_fg_pgid(pid_t pgid){
    void (*old)(int);
    old = signal(SIGTTOU, SIG_IGN);
    tcsetpgrp(STDIN_FILENO,pgid);
    tcsetpgrp(STDOUT_FILENO,pgid);
    signal(SIGTTOU, old);
}

void sigchild_handler (int sig)
{
	pid_t child;
	int status,jobnum;
	char buffer[1024];
	while (( child = waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0){
		jobnum = findjob(jobs,child);
		if (WIFEXITED (status)){
			jobs[jobnum].pids_left -= 1;
			if (jobs[jobnum].pids_left == 0){
				if (jobs[jobnum].status == BG){
					kill(jobs[jobnum].pgid, SIGTTOU);
					printf("\n[%i] + done	%s\n",jobnum,jobs[jobnum].name); 
				}
				deletejob(jobs, jobnum);
				set_fg_pgid(pssh);
			}
		} else if (WIFSIGNALED (status)) {
			set_fg_pgid(pssh);
			deletejob(jobs, jobnum);
		} else if (WIFSTOPPED (status)) {
			set_fg_pgid(pssh);
			jobs[jobnum].status = STOPPED;
			sprintf(buffer,"[%i] + suspended	%s\n", jobnum, jobs[jobnum].name);
			safe_print(buffer);
		} else if (WIFCONTINUED (status)) {
			jobs[jobnum].status = FG;
		} 
	}
}

void jobs_cmd(Job* jobs){	
	int i;
	char buffer[1024];
	for (i = 0; i < MAX_JOBS; i++){
		if (jobs[i].status == STOPPED){
			sprintf(buffer,"[%i] + stopped	%s\n",i, jobs[i].name);
			safe_print(buffer);
		} else if ((jobs[i].status ==  FG) || (jobs[i].status == BG)){
			sprintf(buffer,"[%i] + running	%s\n",i, jobs[i].name);
			safe_print(buffer);
		}
	}
}

void fg_cmd(Job* jobs, Parse* P){
	int jobnum;

	if (P->tasks[0].argv[1] == NULL){
		printf("%s\n","Usage: fg %<job number>");
	} else {
		jobnum = atoi(P->tasks[0].argv[1]+1);
		if ((jobnum == 0) && jobs[jobnum].status == TERM){
			printf("pssh: invalid job number: %s\n", P->tasks[0].argv[1]);
		} else if (jobs[jobnum].status == TERM) {
			printf("pssh: invalid job number: %s\n", P->tasks[0].argv[1]);
		} else {	
			if (jobs[jobnum].status == STOPPED){
				jobs[jobnum].status = FG;
				printf("[%i] + continued	%s\n\n", jobnum ,jobs[jobnum].name);
				set_fg_pgid(jobs[jobnum].pgid);
				kill(-jobs[jobnum].pgid,SIGCONT);		
			} else {
				jobs[jobnum].status = FG;
				printf("%s\n\n", jobs[jobnum].name);
				set_fg_pgid(jobs[jobnum].pgid);
			}	
		}
	}
}

void bg_cmd(Job* jobs, Parse* P){
	int jobnum;

	if (P->tasks[0].argv[1] == NULL){
		printf("%s\n","Usage: bg %<job number>");
	} else {
		jobnum = atoi(P->tasks[0].argv[1]+1);
		if ((jobnum == 0) && jobs[jobnum].status == TERM){
			printf("pssh: invalid job number: %s\n", P->tasks[0].argv[1]);
		} else if (jobs[jobnum].status == TERM) {
			printf("pssh: invalid job number: %s\n", P->tasks[0].argv[1]);
		} else {
			if (jobs[jobnum].status == STOPPED){
				jobs[jobnum].status = FG;
				printf("\n");
				printf("[%i] + continued		%s\n\n", jobnum ,jobs[jobnum].name);
				kill(-jobs[jobnum].pgid,SIGCONT);
			} else {
				jobs[jobnum].status = FG;
				printf("\n");
				printf("%s\n\n", jobs[jobnum].name);
			}
		}
	}
}

void kill_cmd(Job* jobs, Parse* P){
	int i,jobnum,sig,pid;

	if (P->tasks[0].argv[1] == NULL){
		printf("%s\n","Usage: kill [-s <signal>] <pid> | %<job> ...");
	} else {
		if (strcmp(P->tasks[0].argv[1],"-s") == 0) {
			// -s option used
			sig = atoi(P->tasks[0].argv[2]);
			if (P->tasks[0].argv[3][0] == '%') {
				// Killing jobs
				i = 3;
				while(P->tasks[0].argv[i] != NULL){
					jobnum = atoi(P->tasks[0].argv[i]+1);
					if (jobs[jobnum].status == TERM){
						printf("pssh: invalid job number %i\n",jobnum);
					} else {
						kill(-jobs[jobnum].pgid,sig);
						printf("[%i] + done %s\n",jobnum, jobs[jobnum].name);
					}
					i++;
				}
			} else {
				// -s options and PIDS!
				i = 3;
				while(P->tasks[0].argv[i] != NULL){
					pid = atoi(P->tasks[0].argv[i]);
					if (kill(pid,0) == 0){
						kill(pid,sig);
					} else {
						printf("pssh: invalid pid number %i\n",pid);
					}
					i++;
				}
			}
		} else {
			// Use SIGINT instead
			if (P->tasks[0].argv[1][0] == '%'){
				//kill jobs with sigint
				i = 1;
				while(P->tasks[0].argv[i] != NULL){
					jobnum = atoi(P->tasks[0].argv[i]+1);
					if (jobs[jobnum].status == TERM){
						printf("pssh: invalid job number %i\n",jobnum);
					} else {
						kill(-jobs[jobnum].pgid, SIGINT);
						printf("[%i] + done	%s\n",jobnum, jobs[jobnum].name);
					}
					i++;
				}
			} else {
				i = 1;
				while(P->tasks[0].argv[i] != NULL){
					pid = atoi(P->tasks[0].argv[i]);
					if (kill(pid,0) == 0){
						kill(pid,SIGINT);
					} else {
						printf("pssh: invalid pid number %i\n",pid);
					}
					i++;
				}
			}	
		}
	}
}

static void redirect (int fd_old, int fd_new){
	if (fd_new != fd_old) {
		dup2 (fd_new, fd_old);
		close (fd_new);
	}
}

static int close_safe (int fd){
	if ((fd != STDIN_FILENO) && fd != (STDOUT_FILENO)) {
		return close(fd);
	}

	return -1;
}

static void run (Task* T, int in, int out) {
	redirect (STDIN_FILENO, in);
	redirect (STDOUT_FILENO, out);

	if (is_builtin (T->cmd)) {
		builtin_execute(*T);
	} else if (command_found (T->cmd)) {
		execvp (T->cmd, T->argv);
	}
}

static int get_infile (Parse* P) {
	if (P->infile) {
		return open (P->infile, 0);
	} else {
		return STDIN_FILENO;
	}
}

static int get_outfile (Parse* P){
	if (P->outfile) {
		return open (P->outfile, O_CREAT | O_WRONLY, 0664);
	} else {
		return STDOUT_FILENO;
	}
}

static int is_possible(Parse* P){
	unsigned int t;
	Task* T;
	int fd;

	for (t=0; t<P->ntasks; t++) {
		T = &P->tasks[t];
		if (!is_builtin (T->cmd) && !command_found (T->cmd)) {
			fprintf(stderr, "pssh: Command not found: %s\n", T->cmd);
			return 0;
		}

		if (!strcmp (T->cmd, "exit")) {
			exit (EXIT_SUCCESS);
		}
	}

	if (P->infile) {
		if (access (P->infile, R_OK) != 0) {
			fprintf(stderr, "pssh: No such file or directory: %s\n", P->infile);
			return 0;
		}
	}

	if (P->outfile) {
        if ((fd = creat(P->outfile, 0664)) == -1) {
            fprintf(stderr, "pssh: Permission denied: %s\n", P->outfile);
            return 0;
        }
		close (fd);
    }

	return 1;
}

/* Called upon receiving a successful parse.
 * This function is responsible for cycling through the
 * tasks, and forking, executing, etc as necessary to get
 * the job done! */
void execute_tasks (Parse* P, int jobnum){
    unsigned int t = 0;
	int fd[2];
	int in, out;
	pid_t* pid = NULL;

	signal(SIGCHLD, sigchild_handler);
	signal(SIGINT, SIG_DFL);
	signal(SIGTSTP, SIG_DFL);

	if (!is_possible(P)) {
		return;
	}

	jobs[jobnum].pids = malloc(P->ntasks * sizeof(*pid));
	jobs[jobnum].npids = P->ntasks;
	jobs[jobnum].pids_left = P->ntasks;

	pid = jobs[jobnum].pids;
	in = get_infile (P);

	for (t = 0; t < P->ntasks-1; t++) {
		pipe(fd);
		pid[t] = fork();
		setpgid(pid[t], pid[0]);

		if ((t == 0) && (pid[t] > 0)){
			jobs[jobnum].pgid = pid[0];
			if (jobs[jobnum].status != BG) {
				set_fg_pgid(jobs[jobnum].pgid);
			} else {
				set_fg_pgid(pssh);
			}
		}
		if (pid < 0) {
			deletejob(jobs, jobnum);
			exit(EXIT_FAILURE);
		}
		if (!pid[t]) {
			close(fd[READ_SIDE]);
			run(&P->tasks[t], in, fd[WRITE_SIDE]);
		} 

		close(fd[WRITE_SIDE]);
		close_safe(in);

		in = fd[READ_SIDE];
	}

	out = get_outfile(P);
	pid[t] = fork();
	if (!pid[t]) {
		run (&P->tasks[t], in, out);
	}
	close_safe(in);
	close_safe(out);

	for (t = 0; t<P->ntasks; t++) {
		waitpid(pid[t], NULL, 0);
	}

	if (jobs[jobnum].status == BG) {
		printf("[%i] ", jobnum);
		for (t = 0; t < jobs[jobnum].npids; t++) {
			printf("%i ", pid[t]);
		}
		printf("\n");
	}

	free(pid);

}


int main (int argc, char** argv)
{
    char* cmdline;
	char* cmd_cpy;
    Parse* P;
	int jobnum;

	pssh = getpgrp();

    print_banner ();

    while (1) {
		while (tcgetpgrp(STDIN_FILENO) != getpid()) {
			pause();
		}

		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		signal(SIGTSTP, SIG_IGN);
		signal(SIGTTIN, SIG_IGN);
		signal(SIGTTOU, SIG_IGN);

        cmdline = readline (build_prompt());
        if (!cmdline)       /* EOF (ex: ctrl-d) */
            exit (EXIT_SUCCESS);

		strcpy(cmd_cpy, cmdline);

        P = parse_cmdline (cmdline);
        if (!P)
            goto next;

        if (P->invalid_syntax) {
            printf ("pssh: invalid syntax\n");
            goto next;
        }

#if DEBUG_PARSE
        parse_debug (P);
#endif
        if (strcmp(P->tasks[0].cmd, "jobs")==0){
			jobs_cmd(jobs);
			goto next;
		} else if (strcmp(P->tasks[0].cmd, "fg")==0){
			fg_cmd(jobs,P);
			goto next;
		} else if (strcmp(P->tasks[0].cmd, "bg")==0){
			bg_cmd(jobs,P);
			goto next;
		} else if (strcmp(P->tasks[0].cmd, "kill")==0){
			kill_cmd(jobs,P);
			goto next;
		}

		jobnum = addjob(jobs, P, cmd_cpy);
		if (jobnum == -1){
			printf("Failed to create job\n");
			goto next;
		}

		execute_tasks (P, jobnum);

    next:
        parse_destroy (&P);
        free(cmdline);
    }
}
