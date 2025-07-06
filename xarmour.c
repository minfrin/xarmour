/**
 *    Copyright (C) 2025 Graham Leggett <minfrin@sharp.fm>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "config.h"

#define MAX_LINE 1024

#define READ_FD 0
#define WRITE_FD 1

static struct option long_options[] =
{
    {"times", required_argument, NULL, 't'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}
};

static int help(const char *name, const char *msg, int code)
{
    const char *n;

    n = strrchr(name, '/');
    if (!n) {
        n = name;
    }
    else {
        n++;
    }

    fprintf(code ? stderr : stdout,
            "%s\n"
            "\n"
            "NAME\n"
            "  %s - Split armoured data and process each one through a command.\n"
            "\n"
            "SYNOPSIS\n"
            "  %s [-t times] [-v] [-h] [--] command [options]\n"
            "\n"
            "DESCRIPTION\n"
            "\n"
            "  The xarmour command parses multiple armoured text blocks containing\n"
            "  PEM encoded or PGP armoured data, and passes each one to the command\n"
            "  specified via stdin.\n"
            "\n"
            "  All text outside the armoured text block is ignored.\n"
            "\n"
            "OPTIONS\n"
            "  -t, --times t  Number of times command must be successful for xarmour to\n"
            "                 return success. If unset, xarmour will give up on first\n"
            "                 failure.\n"
            "  -h, --help     Display this help message.\n"
            "\n"
            "  -v, --version  Display the version number.\n"
            "\n"
            "ENVIRONMENT\n"
            "  The xarmour tool adds the following environment variables, which can be\n"
            "  used by scripts or for further processing.\n"
            "\n"
            "  XARMOUR_INDEX  Index of armoured text, starting at zero.\n"
            "  XARMOUR_COUNT  Command successes so far.\n"
            "  XARMOUR_TIMES  Times, if set.\n"
            "  XARMOUR_LABEL  Label of the armoured text.\n"
            "\n"
            "RETURN VALUE\n"
            "  The xarmour tool returns the return code from the\n"
            "  first executable to fail.\n"
            "\n"
            "  If the executable was interrupted with a signal, the return\n"
            "  code is the signal number plus 128.\n"
            "\n"
            "  If the executable could not be executed, or if the options\n"
            "  are invalid, the status 1 is returned.\n"
            "\n"
            "  If the times option is specified, we count the number of times the command\n"
            "  was successful. If the threshold was reached, we return 0. If the threshold\n"
            "  was not reached, we return 1. In this mode we process all armoured data even\n"
            "  if we could end early.\n"
            "\n"
            "EXAMPLES\n"
            "  In this trivial example, we print the label of each armoured text found.\n"
            "\n"
            "\t~$ cat chain.pem | xarmour -- printenv XARMOUR_LABEL\n"
            "\n"
            "  In this basic example, we split a series of detached PGP signatures,\n"
            "  passing each signature to the gpg command. If we find two valid signatures,\n"
            "  we succeed.\n"
            "\n"
            "\t~$ cat original_file.asc | xarmour -t 2 -- gpg --verify - original_file\n"
            "\n"
            "AUTHOR\n"
            "  Graham Leggett <minfrin@sharp.fm>\n"
            "", msg ? msg : "", n, n);
    return code;
}

static int version()
{
    printf(PACKAGE_STRING "\n");
    return 0;
}

int main (int argc, char **argv)
{
    int pipefd[2];
    char buffer[MAX_LINE];
    char blabel[MAX_LINE];
    char elabel[MAX_LINE];

    const char *begin = "-----BEGIN %1000[^-]-----";
    const char *end = "-----END %1000[^-]-----";

    const char *name = argv[0];
    long int index = 0, count = 0, times = 0;
    int c, status = 0;

    pid_t f = -1, w;

    while ((c = getopt_long(argc, argv, "t:hv", long_options, NULL)) != -1) {

        switch (c)
        {
        case 't':
            times = strtol(optarg, &optarg, 10);

            if (errno || optarg[0] || times < 1) {
                return help(name, "Count must be bigger than 0.\n", EXIT_FAILURE);
            }

            break;
        case 'h':
            return help(name, NULL, 0);

        case 'v':
            return version();

        default:
            return help(name, NULL, EXIT_FAILURE);

        }

    }

    if (optind == argc) {
        fprintf(stderr, "%s: No command specified.\n", name);
        return EXIT_FAILURE;
    }

    while (fgets(buffer, sizeof(buffer), stdin)) {

        if (f < 0) {

            /* we are seeking the start of the armour */

            if (sscanf(buffer, begin, blabel) == 1) {

                /* start up the command */

                if (pipe(pipefd)) {
                    fprintf(stderr, "%s: Could not create pipe: %s", name,
                            strerror(errno));

                    return EXIT_FAILURE;
                }

                /* Clear any inherited settings */
                signal(SIGCHLD, SIG_DFL);

                f = fork();

                /* error */
                if (f < 0) {
                    fprintf(stderr, "%s: Could not fork: %s", name,
                            strerror(errno));

                    return EXIT_FAILURE;
                }

                /* child */
                else if (f == 0) {

                    char buf[128];

                    snprintf(buf, sizeof(buf), "%ld", index);
                    setenv("XARMOUR_INDEX", buf, 1);

                    snprintf(buf, sizeof(buf), "%ld", count);
                    setenv("XARMOUR_COUNT", buf, 1);

                    snprintf(buf, sizeof(buf), "%ld", times);
                    setenv("XARMOUR_TIMES", buf, 1);

                    setenv("XARMOUR_LABEL", blabel, 1);

                    close(pipefd[WRITE_FD]);
                    dup2(pipefd[READ_FD], STDIN_FILENO);
                    close(pipefd[READ_FD]);

                    execvp(argv[optind], argv + optind);

                    fprintf(stderr, "%s: Could not execute '%s', giving up: %s\n", name,
                            argv[optind], strerror(errno));

                    return EXIT_FAILURE;
                }

                /* parent */
                else {

                    close(pipefd[READ_FD]);

                }

            }

        }

        if (f >= 0) {

            /* write the armour */

            if (write(pipefd[WRITE_FD], buffer, strlen(buffer)) < 0) {
                /* ignore write failures, we'll hear about it below */
            }

            /* we are seeking the end of the armour */

            if (sscanf(buffer, end, elabel) == 1 && !strcmp(blabel, elabel)) {

                index++;

                close(pipefd[WRITE_FD]);

                /* wait for the child process to be done */
                do {
                    w = waitpid(f, &status, 0);
                    if (w == -1 && errno != EINTR) {
                        break;
                    }
                } while (w != f);

                /* waitpid failed, we give up */
                if (w == -1) {

                    fprintf(stderr, "%s: waitpid for '%s' failed: %s\n", name,
                            argv[optind], strerror(errno));

                    return EXIT_FAILURE;
                }

                /* process successful exit */
                else if (WIFEXITED(status) && (WEXITSTATUS(status) == EXIT_SUCCESS)) {

                    /* drop through */
                    count++;
                }

                /* must we ignore failures? */
                else if (times) {

                    /* drop through */
                }

                /* process non success exit */
                else if (WIFEXITED(status)) {

                    fprintf(stderr, "%s: %s returned %d\n", name,
                            argv[optind], status);

                    return WEXITSTATUS(status);
                }

                /* process received a signal */
                else if (WIFSIGNALED(status)) {

                    fprintf(stderr, "%s: %s signaled %d\n", name,
                            argv[optind], status);

                    return WTERMSIG(status) + 128;
                }

                /* otherwise weirdness, just leave */
                else {

                    fprintf(stderr, "%s: %s failed with %d\n", name,
                            argv[optind], status);

                    return EX_OSERR;
                }

                f = -1;

            }


        }

    }

    if (times) {
        if (count < times) {
            fprintf(stderr, "%s: %s: %ld success%s, %ld required: failed\n", name,
                    argv[optind], count, count == 1 ? "" : "es", times);
            return EXIT_FAILURE;
        }
        else {
            fprintf(stderr, "%s: %s: %ld success%s, %ld required: success\n", name,
                    argv[optind], count, count == 1 ? "" : "es", times);
            return EXIT_SUCCESS;
        }
    }

    return EXIT_SUCCESS;
}

