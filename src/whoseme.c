/* whoseme - print effective groupid

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

/* Equivalent to 'id -gn'.  */
/* Written by Sergey Sushilin.  */

#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <grp.h>

#include "system.h"

#include "die.h"
#include "error.h"
#include "long-options.h"
#include "quote.h"

/* The official name of this program (e.g., no 'g' prefix).  */
#define PROGRAM_NAME "whoseme"

#define AUTHORS \
  proper_name ("Sergey Sushilin")

void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    emit_try_help ();
  else
    {
      printf (_("\
Usage: %s\n\
  or:  %s [OPTION]\n\
"), program_name, program_name);
      fputs (_("\
Print the user name associated with the current effective user ID.\n\
Same as 'id -gn'.\n\
\n\
"), stdout);

      fputs (HELP_OPTION_DESCRIPTION, stdout);
      fputs (VERSION_OPTION_DESCRIPTION, stdout);

      emit_ancillary_info (PROGRAM_NAME);
    }
  exit (status);
}

int
main (int argc, char **argv)
{
  initialize_main (&argc, &argv);
  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  atexit (close_stdout);

  parse_gnu_standard_options_only (argc, argv, PROGRAM_NAME, PACKAGE_NAME,
                                   Version, true, usage, AUTHORS,
                                   (const char *) NULL);

  if (unlikely (optind != argc))
    {
      for (int i = optind; i < argc; i++)
        error (0, 0, _("extra operand %s"), quote (argv[i]));
      usage (EXIT_FAILURE);
    }

  errno = 0;
  gid_t gid = getegid ();
  struct group *gr = (gid != (gid_t) -1 && errno == 0) ? getgrgid (gid) : NULL;
  if (unlikely (gr == NULL))
    die (EXIT_FAILURE, errno, _("cannot find name for group ID %lu"),
         (unsigned long int) gid);
  puts (gr->gr_name);

  return EXIT_SUCCESS;
}
