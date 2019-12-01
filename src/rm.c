/* 'rm' file deletion utility for GNU.
   Copyright (C) 1988-2019 Free Software Foundation, Inc.

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

/* Initially written by Paul Rubin, David MacKenzie, and Richard Stallman.
   Reworked to use chdir and avoid recursion, and later, rewritten
   once again, to use fts, by Jim Meyering.  */

#include <config.h>

#include <assert.h>
#include <fnmatch.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/types.h>

#include "system.h"

#include "argmatch.h"
#include "die.h"
#include "error.h"
#include "long-options.h"
#include "priv-set.h"
#include "remove.h"
#include "root-dev-ino.h"
#include "yesno.h"

/* The official name of this program (e.g., no 'g' prefix).  */
#define PROGRAM_NAME "rm"

#define AUTHORS \
  proper_name ("Paul Rubin"), \
  proper_name ("David MacKenzie"), \
  proper_name ("Richard M. Stallman"), \
  proper_name ("Jim Meyering")

/* For long options that have no equivalent short option, use a
   non-character as a pseudo short option, starting with CHAR_MAX + 1.  */
enum
{
  IGNORE_OPTION = CHAR_MAX + 1,
  INTERACTIVE_OPTION,
  ONE_FILE_SYSTEM,
  NO_PRESERVE_ROOT,
  PRESERVE_ROOT,
  PRESUME_INPUT_TTY_OPTION,
  HELP_OPTION,
  VERSION_OPTION
};

static const struct option long_options[] =
{
  {"force", no_argument, NULL, 'f'},
  {"ignore", required_argument, NULL, IGNORE_OPTION},
  {"interactive", optional_argument, NULL, INTERACTIVE_OPTION},
  {"one-file-system", no_argument, NULL, ONE_FILE_SYSTEM},
  {"no-preserve-root", no_argument, NULL, NO_PRESERVE_ROOT},
  {"preserve-root", optional_argument, NULL, PRESERVE_ROOT},

  /* This is solely for testing.  Do not document.  */
  /* It is relatively difficult to ensure that there is a tty on stdin.
     Since rm acts differently depending on that, without this option,
     it'd be harder to test the parts of rm that depend on that setting.  */
  {"-presume-input-tty", no_argument, NULL, PRESUME_INPUT_TTY_OPTION},
  {"recursive", no_argument, NULL, 'r'},
  {"dir", no_argument, NULL, 'd'},
  {"verbose", no_argument, NULL, 'v'},
  {"help", no_argument, NULL, HELP_OPTION},
  {"version", no_argument, NULL, VERSION_OPTION},
  {NULL, 0, NULL, 0}
};

enum interactive_type
{
  interactive_never, /* 0: no option or --interactive=never */
  interactive_once,  /* 1: -I or --interactive=once */
  interactive_always /* 2: default, -i or --interactive=always */
};
static const char *const interactive_args[] =
{
  "never",
  "no",
  "none",
  "once",
  "always",
  "yes",
  NULL
};
static const enum interactive_type interactive_types[] =
{
  interactive_never, interactive_never, interactive_never,
  interactive_once,
  interactive_always, interactive_always
};

ARGMATCH_VERIFY (interactive_args, interactive_types);

/* A linked list of shell-style globbing patterns.  If a non-argument
   file name matches any of these patterns, it is ignored.
   Controlled by --ignore.  Multiple --ignore options accumulate.  */
struct ignore_pattern
{
  const char *pattern;
  struct ignore_pattern *next;
};

static struct ignore_pattern *ignore_patterns;

/* Advise the user about invalid usages like "rm -foo" if the file
   "-foo" exists, assuming ARGC and ARGV are as with 'main'.  */
static void
diagnose_leading_hyphen (int argc, char **argv)
{
  /* OPTIND is unreliable, so iterate through the arguments looking
     for a file name that looks like an option.  */

  for (int i = 1; i < argc; i++)
    {
      const char *arg = argv[i];
      struct stat st;

      if (arg[0] == '-' && arg[1] && lstat (arg, &st) == 0)
        {
          fprintf (stderr,
                   _("Try '%s ./%s' to remove the file %s.\n"),
                   argv[0],
                   quotearg_n_style (1, shell_escape_quoting_style, arg),
                   quoteaf (arg));
        }
    }
}

/* Add 'pattern' to the list of patterns for which files that match are
   not listed.  */
static void
add_ignore_pattern (const char *pattern)
{
  struct ignore_pattern *ignore;

  ignore = xmalloc (sizeof (*ignore));
  ignore->pattern = pattern;
  /* Add it to the head of the linked list.  */
  ignore->next = ignore_patterns;
  ignore_patterns = ignore;
}

/* Return true if one of the PATTERNS matches FILE.  */
static bool
patterns_match (const struct ignore_pattern *patterns, const char *file)
{
  for (const struct ignore_pattern *p = patterns; p != NULL; p = p->next)
    if (fnmatch (p->pattern, file, FNM_PERIOD) == 0)
      return true;
  return false;
}

/* Return true if FILE should be ignored.  */
static bool
file_ignored (const char *file)
{
  return patterns_match (ignore_patterns, file);
}

void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    emit_try_help ();
  else
    {
      printf (_("Usage: %s [OPTION]... [FILE]...\n"), program_name);
      fputs (_("\
Remove (unlink) the FILE(s).\n\
\n\
  -f, --force           ignore nonexistent files and arguments, never prompt\n\
      --ignore=PATTERN  do not remove implied entries matching shell PATTERN\n\
  -i                    prompt before every removal\n\
"), stdout);
      fputs (_("\
  -I                    prompt once before removing more than three files, or\n\
                          when removing recursively; less intrusive than -i,\n\
                          while still giving protection against most mistakes\n\
      --interactive[=WHEN]  prompt according to WHEN: never, once (-I), or\n\
                              always (-i); without WHEN, prompt always\n\
"), stdout);
      fputs (_("\
      --one-file-system  when removing a hierarchy recursively, skip any\n\
                           directory that is on a file system different from\n\
                           that of the corresponding command line argument\n\
"), stdout);
      fputs (_("\
      --no-preserve-root  do not treat '/' specially\n\
      --preserve-root[=all]  do not remove '/' (default);\n\
                              with 'all', reject any command line argument\n\
                              on a separate device from its parent\n\
"), stdout);
      fputs (_("\
  -r, -R, --recursive   remove directories and their contents recursively\n\
  -d, --dir             remove empty directories\n\
  -v, --verbose         explain what is being done\n\
"), stdout);

      fputs (HELP_OPTION_DESCRIPTION, stdout);
      fputs (VERSION_OPTION_DESCRIPTION, stdout);

      fputs (_("\
\n\
By default, rm does not remove directories.  Use the --recursive (-r or -R)\n\
option to remove each listed directory, too, along with all of its contents.\n\
"), stdout);
      printf (_("\
\n\
To remove a file whose name starts with a '-', for example '-foo',\n\
use one of these commands:\n\
  %s -- -foo\n\
\n\
  %s ./-foo\n\
"), program_name, program_name);
      fputs (_("\
\n\
Note that if you use rm to remove a file, it might be possible to recover\n\
some of its contents, given sufficient expertise and/or time.  For greater\n\
assurance that the contents are truly unrecoverable, consider using shred.\n\
"), stdout);
      emit_ancillary_info (PROGRAM_NAME);
    }
  exit (status);
}

static void
rm_option_init (struct rm_options *x)
{
  x->ignore_missing_files = false;
  x->interactive = RMI_SOMETIMES;
  x->one_file_system = false;
  x->remove_empty_directories = false;
  x->recursive = false;
  x->root_dev_ino = NULL;
  x->preserve_all_root = false;
  x->stdin_tty = isatty (STDIN_FILENO);
  x->verbose = false;

  /* Since this program exits immediately after calling 'rm', rm need not
     expend unnecessary effort to preserve the initial working directory.  */
  x->require_restore_cwd = false;
}

int
main (int argc, char **argv)
{
  bool preserve_root = true;
  struct rm_options x;
  bool prompt_once = false;
  int optc = -1;

  initialize_main (&argc, &argv);
  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  atexit (close_stdin);

  rm_option_init (&x);

  /* Try to disable the ability to unlink a directory.  */
  priv_set_remove_linkdir ();

  parse_long_options (argc, argv, PROGRAM_NAME, PACKAGE_NAME, Version, usage, AUTHORS,
                      (const char *) NULL);

  while ((optc = getopt_long (argc, argv, "dfirvIR", long_options, NULL)) != -1)
    {
      switch (optc)
        {
        case 'd':
          x.remove_empty_directories = true;
          break;
        case 'f':
          x.interactive = RMI_NEVER;
          x.ignore_missing_files = true;
          prompt_once = false;
          break;
        case 'i':
          x.interactive = RMI_ALWAYS;
          x.ignore_missing_files = false;
          prompt_once = false;
          break;
        case 'I':
          x.interactive = RMI_SOMETIMES;
          x.ignore_missing_files = false;
          prompt_once = true;
          break;
        case 'r':
        case 'R':
          x.recursive = true;
          break;
        case IGNORE_OPTION:
          add_ignore_pattern (optarg);
          break;
        case INTERACTIVE_OPTION:
          {
            int i;
            if (optarg != NULL)
              i = XARGMATCH ("--interactive", optarg, interactive_args, interactive_types);
            else
              i = interactive_always;
            switch (i)
              {
              case interactive_never:
                x.interactive = RMI_NEVER;
                prompt_once = false;
                break;
              case interactive_once:
                x.interactive = RMI_SOMETIMES;
                x.ignore_missing_files = false;
                prompt_once = true;
                break;
              case interactive_always:
                x.interactive = RMI_ALWAYS;
                x.ignore_missing_files = false;
                prompt_once = false;
                break;
              }
            break;
          }
        case ONE_FILE_SYSTEM:
          x.one_file_system = true;
          break;
        case NO_PRESERVE_ROOT:
          if (!STREQ (argv[optind - 1], "--no-preserve-root"))
            die (EXIT_FAILURE, 0, _("you may not abbreviate the --no-preserve-root option"));
          preserve_root = false;
          break;
        case PRESERVE_ROOT:
          if (optarg != NULL)
            {
              if STREQ (optarg, "all")
                x.preserve_all_root = true;
              else
                die (EXIT_FAILURE, 0, _("unrecognized --preserve-root argument: %s"),
                     quoteaf (optarg));
            }
          preserve_root = true;
          break;
        case PRESUME_INPUT_TTY_OPTION:
          x.stdin_tty = true;
          break;
        case 'v':
          x.verbose = true;
          break;
        default:
          diagnose_leading_hyphen (argc, argv);
          usage (EXIT_FAILURE);
        }
    }

  if (argc <= optind)
    {
      if (x.ignore_missing_files)
        return EXIT_SUCCESS;
      else
        {
          error (0, 0, _("missing operand"));
          usage (EXIT_FAILURE);
        }
    }

  if (x.recursive && preserve_root)
    {
      static struct dev_ino dev_ino_buf;
      x.root_dev_ino = get_root_dev_ino (&dev_ino_buf);
      if (x.root_dev_ino == NULL)
        die (EXIT_FAILURE, errno, _("failed to get attributes of %s"),
             quoteaf ("/"));
    }

  int n_files = argc - optind;
  char **file = argv + optind;

  if (prompt_once && (x.recursive || n_files > 3))
    {
      fprintf (stderr,
               (x.recursive
                ? S_("%s: remove %i argument recursively? ",
                     "%s: remove %i arguments recursively? ",
                     select_plural (n_files))
                : S_("%s: remove %i argument? ",
                     "%s: remove %i arguments? ",
                     select_plural (n_files))),
               program_name, n_files);
      if (!yesno ())
        return EXIT_SUCCESS;
    }

  for (int i = 0; file[i] != NULL; i++)
    {
      if (file_ignored (file[i]))
        {
          file[i] = file[n_files - 1];
          file[n_files - 1] = NULL;
        }
    }

  enum RM_status status = rm (file, &x);
  assert (VALID_STATUS (status));
  return status == RM_ERROR ? EXIT_FAILURE : EXIT_SUCCESS;
}
