/* groups -- print the groups a user is in
   Copyright (C) 1989-2019 Free Software Foundation, Inc.

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

/* Written by James Youngman based on id.c and groups.sh,
   which were written by Arnold Robbins and David MacKenzie.  */

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>

#include "system.h"
#include "die.h"
#include "group-list.h"
#include "quote.h"

/* The official name of this program (e.g., no 'g' prefix).  */
#define PROGRAM_NAME "groups"

#define AUTHORS \
  proper_name ("David MacKenzie"), \
  proper_name ("James Youngman")

void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    emit_try_help ();
  else
    {
      printf (_("Usage: %s [OPTION]... [USERNAME]...\n"), program_name);
      fputs (_("\
Print group memberships for each USERNAME or, if no USERNAME is specified, for\
\n\
the current process (which may differ if the groups database has changed).\n"),
             stdout);
      fputs (HELP_OPTION_DESCRIPTION, stdout);
      fputs (VERSION_OPTION_DESCRIPTION, stdout);
      emit_ancillary_info (PROGRAM_NAME);
    }
  exit (status);
}

int
main (int argc, char **argv)
{
  bool ok = true;
  gid_t rgid, egid;
  uid_t ruid;

  initialize_main (&argc, &argv);
  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  atexit (close_stdout);

  /* Processing the arguments this way makes groups.c behave differently to
   * groups.sh if one of the arguments is "--".
   */
  parse_long_options (argc, argv, PROGRAM_NAME, PACKAGE_NAME, Version, usage, AUTHORS,
                      (const char *) NULL);

  if (optind == argc)
    {
      /* No arguments.  Divulge the details of the current process.  */
      uid_t NO_UID = -1;
      gid_t NO_GID = -1;

      errno = 0;
      ruid = getuid ();
      if (ruid == NO_UID && errno)
        die (EXIT_FAILURE, errno, _("cannot get real UID"));

      errno = 0;
      egid = getegid ();
      if (egid == NO_GID && errno)
        die (EXIT_FAILURE, errno, _("cannot get effective GID"));

      errno = 0;
      rgid = getgid ();
      if (rgid == NO_GID && errno)
        die (EXIT_FAILURE, errno, _("cannot get real GID"));

      if (!print_group_list (NULL, ruid, rgid, egid, true, ' '))
        ok = false;
      putchar ('\n');
    }
  else
    {
      /* At least one argument.  Divulge the details of the specified users.  */
      for ( ; optind < argc; optind++)
        {
          struct passwd *pwd = getpwnam (argv[optind]);
          if (pwd == NULL)
            {
              error (0, 0, _("%s: no such user"), quote (argv[optind]));
              ok = false;
              continue;
            }
          ruid = pwd->pw_uid;
          rgid = egid = pwd->pw_gid;

          printf ("%s : ", argv[optind]);
          if (!print_group_list (argv[optind], ruid, rgid, egid, true, ' '))
            ok = false;
          putchar ('\n');
        }
    }

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
