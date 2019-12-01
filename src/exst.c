/* exst - print an exit status of executed program
   Copyright (C) 2019 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* Written by Sergey Sushilin.  */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "system.h"

#include "die.h"
#include "filenamecat.h"
#include "long-options.h"

/* The official name of this program (e.g., no 'g' prefix).  */
#define PROGRAM_NAME "exst"

#define AUTHORS \
  proper_name ("Sergey Sushilin")

void
usage (int status)
{
  if (status != 0)
    emit_try_help ();
  else
    {
      printf (_("\
Usage: %s [OPTION]\n\
  Or:  %s <program> arg1 arg2 arg3...\n\
\n\
"), program_name, program_name);

      fputs (HELP_OPTION_DESCRIPTION, stdout);
      fputs (VERSION_OPTION_DESCRIPTION, stdout);

      emit_ancillary_info (PROGRAM_NAME);
    }

  exit (status);
}

static const struct
{
  const int  constant;
  const char *name;
  const char *description;
} signals[] =
{
#define SET(constant, name, description) { constant, name, description }
# include "signals.def"
#undef SET
};

static bool
is_file_exist (const char *file, struct stat *st)
{
  if (is_absolute_path (file) || (*file == '.' && ((*(file + 1) == '.' && *(file + 2) == '/') || *(file + 1) == '/')))
    return stat (file, st) == 0;
  else
    {
      char *path = getenv ("PATH");
      if (path == NULL || *path == '\0')
        return false;
      path = xstrdup (path);
      for (char *dir = strtok (path, ":"); dir != NULL; dir = strtok (NULL, ":"))
        {
          char *candidate = file_name_concat (dir, file, NULL);
          if (stat (candidate, st) == 0)
            {
              free (candidate);
              return true;
            }
          free (candidate);
        }
      return false;
    }
}

int
main (int argc, char **argv)
{
  struct stat st;

  initialize_main (&argc, &argv);
  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  atexit (close_stdout);

  parse_gnu_standard_options_only (argc, argv, PROGRAM_NAME, PACKAGE_NAME,
                                   Version, false, usage, AUTHORS,
                                   (const char *) NULL);

  if (argc <= 1)
    {
      error (0, 0, _("too few arguments"));
      usage (EXIT_FAILURE);
    }
  else
    {
      char **arg = argv + optind;

      if (!is_file_exist (*arg, &st))
        die (EXIT_ENOENT, 0, _("cannot find %s"), quoteaf (*arg));
      if ((st.st_mode & X_OK) == 0)
        die (EXIT_CANNOT_INVOKE, 0, _("%s is not executable"), quoteaf (*arg));
      if (S_ISDIR (st.st_mode))
        die (EXIT_CANNOT_INVOKE, EISDIR, "%s", quotef (*arg));

      pid_t pid = fork ();

      if (pid < 0)
        die (EXIT_CANCELED, errno, _("fork call failed"));
      else if (pid == 0)
        {
          /* Child.  */
          execvp (*arg, arg);
          die (EXIT_CANNOT_INVOKE, errno, "%s", quotef (*arg));
        }
      else
        {
          /* Parent.  */
          int status = 0;
          do
            {
            #if defined(__NeXT__)
              if ((wait4 (pid, &status, WUNTRACED | WCONTINUED, NULL)) < 0)
                die (EXIT_FAILURE, errno, _("wait4 call failed"));
            #else
              if ((waitpid (pid, &status, WUNTRACED | WCONTINUED)) < 0)
                die (EXIT_FAILURE, errno, _("waitpid call failed"));
            #endif

              if (WIFEXITED (status))
                printf (_("%s: %s (process %lu) exited with status %i.\n"), program_name, quoteaf (*arg), (unsigned long int) pid,
                        WEXITSTATUS (status));
              else if (WIFSIGNALED (status))
                printf (_("%s: %s (process %lu) received signal %s, %s.\n"), program_name, quoteaf (*arg), (unsigned long int) pid,
                        signals[WTERMSIG (status)].name, signals[WTERMSIG (status)].description);
              else if (WIFSTOPPED (status))
                printf (_("%s: %s (process %lu) stopped by signal %s, %s.\n"), program_name, quoteaf (*arg), (unsigned long int) pid,
                        signals[WSTOPSIG (status)].name, signals[WSTOPSIG (status)].description);
              else if (WIFCONTINUED (status))
                printf (_("%s: %s (process %lu) continued.\n"), program_name, quoteaf (*arg), (unsigned long int) pid);
            }
          while (!WIFEXITED (status) && !WIFSIGNALED (status));
        }
    }

  return 0;
}
