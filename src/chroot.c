/* chroot -- run command or shell with special root directory
   Copyright (C) 1995-2019 Free Software Foundation, Inc.

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

/* Written by Roland McGrath.  */

#include <config.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "system.h"

#include "die.h"
#include "error.h"
#include "ignore-value.h"
#include "mgetgroups.h"
#include "quote.h"
#include "root-dev-ino.h"
#include "long-options.h"
#include "userspec.h"
#include "xstrtol.h"

/* The official name of this program (e.g., no 'g' prefix).  */
#define PROGRAM_NAME "chroot"

#define AUTHORS proper_name ("Roland McGrath")

#ifndef MAXGID
# define MAXGID GID_T_MAX
#endif

static inline bool uid_unset (uid_t uid) { return uid == (uid_t) -1; }
static inline bool gid_unset (gid_t gid) { return gid == (gid_t) -1; }
#define uid_set(x) (!uid_unset (x))
#define gid_set(x) (!gid_unset (x))

enum
{
  GROUPS = UCHAR_MAX + 1,
  USERSPEC,
  SKIP_CHDIR
};

static const struct option long_options[] =
{
  {"groups", required_argument, NULL, GROUPS},
  {"userspec", required_argument, NULL, USERSPEC},
  {"skip-chdir", no_argument, NULL, SKIP_CHDIR},
  {NULL, 0, NULL, '\0'}
};

#if !HAVE_SETGROUPS
/* At least Interix lacks supplemental group support.  */
static int
setgroups (size_t size, const gid_t *list _GL_UNUSED)
{
  if (size == 0)
    {
      /* Return success when clearing supplemental groups
         as !HAVE_SETGROUPS should only be the case on
         platforms that do not support supplemental groups.  */
      return 0;
    }
  else
    {
      errno = ENOTSUP;
      return -1;
    }
}
#endif

/* Determine the group IDs for the specified supplementary GROUPS,
   which is a comma separated list of supplementary groups (names or numbers).
   Allocate an array for the parsed IDs and store it in PGIDS,
   which may be allocated even on parse failure.
   Update the number of parsed groups in PN_GIDS on success.
   Upon any failure return nonzero, and issue diagnostic if SHOW_ERRORS is true.
   Otherwise return zero.  */

static int
parse_additional_groups (const char *groups, GETGROUPS_T **pgids,
                         size_t *pn_gids, bool show_errors)
{
  GETGROUPS_T *gids = NULL;
  size_t n_gids_allocated = 0;
  size_t n_gids = 0;
  char *buffer = xstrdup (groups);
  const char *tmp;
  int ret = 0;

  for (tmp = strtok (buffer, ","); tmp; tmp = strtok (NULL, ","))
    {
      struct group *g;
      uintmax_t value;

      if (xstrtoumax (tmp, NULL, 10, &value, "") == LONGINT_OK
          && value <= MAXGID)
        {
          while (isspace (to_uchar (*tmp)))
            tmp++;
          if (*tmp != '+')
            {
              /* Handle the case where the name is numeric.  */
              g = getgrnam (tmp);
              if (g != NULL)
                value = g->gr_gid;
            }
          /* Flag that we have got a group from the number.  */
          g = (struct group *) (intptr_t) ! NULL;
        }
      else
        {
          g = getgrnam (tmp);
          if (g != NULL)
            value = g->gr_gid;
        }

      if (g == NULL)
        {
          ret = -1;

          if (show_errors)
            {
              error (0, errno, _("invalid group %s"), quote (tmp));
              continue;
            }

          break;
        }

      if (n_gids == n_gids_allocated)
        gids = X2NREALLOC (gids, &n_gids_allocated);
      gids[n_gids++] = value;
    }

  if (ret == 0 && n_gids == 0)
    {
      if (show_errors)
        error (0, 0, _("invalid group list %s"), quote (groups));
      ret = -1;
    }

  *pgids = gids;

  if (ret == 0)
    *pn_gids = n_gids;

  free (buffer);
  return ret;
}

/* Return whether the passed path is equivalent to "/".
   Note we do not compare against get_root_dev_ino() as "/"
   could be bind mounted to a separate location.  */
static bool
is_root (const char *dir)
{
  char *resolved = canonicalize_file_name (dir);
  bool is_res_root = resolved != NULL && STREQ ("/", resolved);
  free (resolved);
  return is_res_root;
}

void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    emit_try_help ();
  else
    {
      printf (_("\
Usage: %s [OPTION] NEWROOT [COMMAND [ARG]...]\n\
  or:  %s OPTION\n\
"), program_name, program_name);

      fputs (_("\
Run COMMAND with root directory set to NEWROOT.\n\
\n\
"), stdout);

      fputs (_("\
  --groups=G_LIST        specify supplementary groups as g1,g2,..,gN\n\
"), stdout);
      fputs (_("\
  --userspec=USER:GROUP  specify user and group (ID or name) to use\n\
"), stdout);
      printf (_("\
  --skip-chdir           do not change working directory to %s\n\
"), quoteaf ("/"));

      fputs (HELP_OPTION_DESCRIPTION, stdout);
      fputs (VERSION_OPTION_DESCRIPTION, stdout);
      fputs (_("\
\n\
If no command is given, run '\"$SHELL\" -i' (default: '/bin/sh -i').\n\
"), stdout);
      emit_ancillary_info (PROGRAM_NAME);
    }

  exit (status);
}

int
main (int argc, char **argv)
{
  int optc;

  /* Input user and groups spec.  */
  char *userspec = NULL;
  const char *username = NULL;
  const char *groups = NULL;
  bool skip_chdir = false;

  /* Parsed user and group IDs.  */
  uid_t uid = -1;
  gid_t gid = -1;
  GETGROUPS_T *out_gids = NULL;
  size_t n_gids = 0;

  initialize_main (&argc, &argv);
  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  initialize_exit_failure (EXIT_CANCELED);
  atexit (close_stdout);

  parse_long_options (argc, argv, PROGRAM_NAME, PACKAGE_NAME, Version, usage, AUTHORS,
                      (const char *) NULL);

  while ((optc = getopt_long (argc, argv, "+", long_options, NULL)) != -1)
    switch (optc)
      {
      case USERSPEC:
        {
          userspec = optarg;
          /* Treat 'user:' just like 'user'
             as we lookup the primary group by default
             (and support doing so for UIDs as well as names.  */
          size_t userlen = strlen (userspec);
          if (userlen != 0 && userspec[userlen - 1] == ':')
            userspec[userlen - 1] = '\0';
          break;
        }
      case GROUPS:
        groups = optarg;
        break;
      case SKIP_CHDIR:
        skip_chdir = true;
        break;
      default:
        usage (EXIT_CANCELED);
      }

  if (argc <= optind)
    {
      error (0, 0, _("missing operand"));
      usage (EXIT_CANCELED);
    }

  const char *newroot = argv[optind];
  bool is_oldroot = is_root (newroot);

  if (!is_oldroot && skip_chdir)
    {
      error (0, 0, _("option --skip-chdir only permitted if NEWROOT is old %s"),
             quoteaf ("/"));
      usage (EXIT_CANCELED);
    }

  if (!is_oldroot)
    {
      /* We have to look up users and groups twice.
         - First, outside the chroot to load potentially necessary passwd/group
           parsing plugins (e.g. NSS);
         - Second, inside chroot to redo parsing in case IDs are different.
           Within chroot lookup is the main justification for having
           the --user option supported by the chroot command itself.  */
      if (userspec != NULL)
        ignore_value (parse_user_spec (userspec, &uid, &gid, NULL, NULL));

      /* If no gid is supplied or looked up, do so now.
         Also lookup the username for use with getgroups.  */
      if (uid_set (uid) && (!groups || gid_unset (gid)))
        {
          const struct passwd *pwd;
          if ((pwd = getpwuid (uid)) != NULL)
            {
              if (gid_unset (gid))
                gid = pwd->pw_gid;
              username = pwd->pw_name;
            }
        }

      if (groups != NULL && *groups != '\0')
        ignore_value (parse_additional_groups (groups, &out_gids, &n_gids,
                                               false));
#if HAVE_SETGROUPS
      else if (!groups && gid_set (gid) && username)
        {
          int ngroups = xgetgroups (username, gid, &out_gids);
          if (ngroups > 0)
            n_gids = ngroups;
        }
#endif
    }

  if (chroot (newroot) != 0)
    die (EXIT_CANCELED, errno, _("cannot change root directory to %s"),
         quoteaf (newroot));

  if (!skip_chdir && chdir ("/") != 0)
    die (EXIT_CANCELED, errno, _("cannot chdir to root directory"));

  if (argc == optind + 1)
    {
      /* No command.  Run an interactive shell.  */
      char *shell = getenv ("SHELL");
      if (shell == NULL)
        shell = bad_cast ("/bin/sh");
      argv[0] = shell;
      argv[1] = bad_cast ("-i");
      argv[2] = NULL;
    }
  else
    /* The following arguments give the command.  */
    argv += optind + 1;

  /* Attempt to set all three: supplementary groups, group ID, user ID.
     Diagnose any failures.  If any have failed, exit before execvp.  */
  if (userspec != NULL)
    {
      const char *err = parse_user_spec (userspec, &uid, &gid, NULL, NULL);

      if (err != 0 && uid_unset (uid) && gid_unset (gid))
        die (EXIT_CANCELED, errno, "%s", (err));
    }

  /* If no gid is supplied or looked up, do so now.
     Also lookup the username for use with getgroups.  */
  if (uid_set (uid) && (groups == NULL || gid_unset (gid)))
    {
      const struct passwd *pwd;
      if ((pwd = getpwuid (uid)) != NULL)
        {
          if (gid_unset (gid))
            gid = pwd->pw_gid;
          username = pwd->pw_name;
        }
      else if (gid_unset (gid))
        die (EXIT_CANCELED, errno,
             _("no group specified for unknown uid: %d"), (int) uid);
    }

  GETGROUPS_T *gids = out_gids;
  GETGROUPS_T *in_gids = NULL;
  if (groups != NULL && *groups != '\0')
    {
      if (parse_additional_groups (groups, &in_gids, &n_gids, !n_gids) != 0)
        {
          if (!n_gids)
            return EXIT_CANCELED;
          /* else look-up outside the chroot worked, then go with those.  */
        }
      else
        gids = in_gids;
    }
#if HAVE_SETGROUPS
  else if (groups == NULL && gid_set (gid) && username != NULL)
    {
      int ngroups = xgetgroups (username, gid, &in_gids);
      if (ngroups <= 0)
        {
          if (n_gids == 0)
            die (EXIT_CANCELED, errno,
                 _("failed to get supplemental groups"));
          /* else look-up outside the chroot worked, then go with those.  */
        }
      else
        {
          n_gids = ngroups;
          gids = in_gids;
        }
    }
#endif

  if ((uid_set (uid) || groups != NULL) && setgroups (n_gids, gids) != 0)
    die (EXIT_CANCELED, errno, _("failed to set supplemental groups"));

  free (in_gids);
  free (out_gids);

  if (gid_set (gid) && setgid (gid))
    die (EXIT_CANCELED, errno, _("failed to set group-ID"));

  if (uid_set (uid) && setuid (uid))
    die (EXIT_CANCELED, errno, _("failed to set user-ID"));

  /* Execute the given command.  */
  execvp (argv[0], argv);

  int exit_status = (errno == ENOENT ? EXIT_ENOENT : EXIT_CANNOT_INVOKE);
  error (0, errno, _("failed to run command %s"), quote (argv[0]));
  return exit_status;
}
