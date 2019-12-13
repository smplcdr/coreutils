/* xchg - exchange the contents of two files
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

#include <assert.h>
#include <getopt.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "system.h"

#include "backupfile.h"
#include "copy.h"
#include "cp-hash.h"
#include "die.h"
#include "error.h"
#include "filenamecat.h"
#include "long-options.h"
#include "remove.h"
#include "renameatu.h"
#include "root-dev-ino.h"
#include "same.h"
#include "tempname.h"
#include "xdectoint.h"

/* The official name of this program (e.g., no 'g' prefix).  */
#define PROGRAM_NAME "xchg"

#define AUTHORS \
  proper_name ("Sergey Sushilin")

static const struct option long_options[] =
{
  {"shift", required_argument, NULL, 's'},
  {NULL, 0, NULL, '\0'}
};

static void
cp_option_init (struct cp_options *x)
{
  bool selinux_enabled = (is_selinux_enabled () > 0);

  cp_options_default (x);
  x->copy_as_regular = false; /* FIXME: maybe make this an option */
  x->reflink_mode = REFLINK_AUTO;
  x->dereference = DEREF_NEVER;
  x->unlink_dest_before_opening = false;
  x->unlink_dest_after_failed_open = false;
  x->hard_link = false;
  x->interactive = I_UNSPECIFIED;
  x->move_mode = true;
  x->install_mode = false;
  x->one_file_system = false;
  x->preserve_ownership = true;
  x->preserve_links = true;
  x->preserve_mode = true;
  x->preserve_timestamps = true;
  x->explicit_no_preserve_mode= false;
  x->preserve_security_context = selinux_enabled;
  x->set_security_context = false;
  x->reduce_diagnostics = false;
  x->data_copy_required = true;
  x->require_preserve = false; /* FIXME: maybe make this an option */
  x->require_preserve_context = false;
  x->preserve_xattr = true;
  x->require_preserve_xattr = false;
  x->recursive = true;
  x->sparse_mode = SPARSE_AUTO; /* FIXME: maybe make this an option */
  x->symbolic_link = false;
  x->set_mode = false;
  x->mode = 0;
  x->stdin_tty = isatty (STDIN_FILENO);

  x->open_dangling_dest_symlink = false;
  x->update = false;
  x->verbose = false;
  x->dest_info = NULL;
  x->src_info = NULL;
}

static void
rm_option_init (struct rm_options *x)
{
  x->ignore_missing_files = false;
  x->remove_empty_directories = true;
  x->recursive = true;
  x->one_file_system = false;

  /* Should we prompt for removal, too?  No.  Prompting for the 'move'
     part is enough.  It implies removal.  */
  x->interactive = RMI_NEVER;
  x->stdin_tty = false;

  x->verbose = false;

  /* Since this program may well have to process additional command
     line arguments after any call to 'rm', that function must preserve
     the initial working directory, in case one of those is a
     '.'-relative name.  */
  x->require_restore_cwd = true;

  {
    static struct dev_ino dev_ino_buf;
    x->root_dev_ino = get_root_dev_ino (&dev_ino_buf);
    if (x->root_dev_ino == NULL)
      die (EXIT_FAILURE, errno, _("failed to get attributes of %s"),
           quoteaf ("/"));
  }

  x->preserve_all_root = false;
}

/* Move SOURCE onto DEST.  Handles cross-file-system moves.
   If SOURCE is a directory, DEST must not exist.
   Return true if successful.  */
static bool
do_move (const char *source, const char *dest, const struct cp_options *x)
{
  bool copy_into_self;
  bool rename_succeeded;
  bool ok = copy (source, dest, false, x, &copy_into_self, &rename_succeeded);

  if (ok)
    {
      const char *dir_to_remove;
      if (copy_into_self)
        {
          /* In general, when copy returns with copy_into_self set, SOURCE is
             the same as, or a parent of DEST.  In this case we know it is a
             parent.  It does not make sense to move a directory into itself, and
             besides in some situations doing so would give highly nonintuitive
             results.  Run this 'mkdir b; touch a c; mv * b' in an empty
             directory.  Here is the result of running echo $(find b -print):
             b b/a b/b b/b/a b/c.  Notice that only file 'a' was copied
             into b/b.  Handle this by giving a diagnostic, removing the
             copied-into-self directory, DEST ('b/b' in the example),
             and failing.  */

          dir_to_remove = NULL;
          ok = false;
        }
      else if (rename_succeeded)
        {
          /* No need to remove anything.  SOURCE was successfully
             renamed to DEST.  Or the user declined to rename a file.  */
          dir_to_remove = NULL;
        }
      else
        {
          /* This may mean SOURCE and DEST referred to different devices.
             It may also conceivably mean that even though they referred
             to the same device, rename wasn't implemented for that device.

             E.g., (from Joel N. Weber),
             [...] there might someday be cases where you cannot rename
             but you can copy where the device name is the same, especially
             on Hurd.  Consider an ftpfs with a primitive ftp server that
             supports uploading, downloading and deleting, but not renaming.

             Also, note that comparing device numbers is not a reliable
             check for 'can-rename'.  Some systems can be set up so that
             files from many different physical devices all have the same
             st_dev field.  This is a feature of some NFS mounting
             configurations.

             We reach this point if SOURCE has been successfully copied
             to DEST.  Now we have to remove SOURCE.

             This function used to resort to copying only when rename
             failed and set errno to EXDEV.  */

          dir_to_remove = source;
        }

      if (dir_to_remove != NULL)
        {
          struct rm_options rm_options;
          enum RM_status status;
          const char *dir[2];

          rm_option_init (&rm_options);
          rm_options.verbose = x->verbose;
          dir[0] = dir_to_remove;
          dir[1] = NULL;

          status = rm ((void *) dir, &rm_options);
          assert (VALID_STATUS (status));
          if (status == RM_ERROR)
            ok = false;
        }
    }

  return ok;
}

void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    emit_try_help ();
  else
    {
      printf (_("\
Usage: %s [FILES...]\n\
  or:  %s [OPTION]\n\
"), program_name, program_name);

      fputs (_("\
Exchange files.\n\
"), stdout);
      fputs (_("\
FILES must be of the same type.\n\
\n\
"), stdout);

      fputs (_("\
  -s, --shift          shift of exchanging files\n\
"), stdout);

      fputs (HELP_OPTION_DESCRIPTION, stdout);
      fputs (VERSION_OPTION_DESCRIPTION, stdout);

      emit_ancillary_info (PROGRAM_NAME);
    }
  exit (status);
}

static size_t
count_consecutive_X_s (const char *s, size_t len)
{
  size_t n;
  for (n = 0; len != 0 && s[len - 1] == 'X'; len--)
    n++;
  return n;
}
static int
mktemp_len (char *template, size_t suff_len, size_t x_len, bool isdir, bool create)
{
  return gen_tempname_len (template, suff_len, /* flags */ 0, create ? (isdir ? GT_DIR : GT_FILE) : GT_NOCREATE, x_len);
}

static char *
mktmp (const char *template, bool isdir)
{
  char *env = getenv ("TMPDIR");
  char *tmp_dir = (env != NULL && *env != '\0' ? env : (char *) "/tmp");

  char *x_suff = strchr (template, 'X');
  if (x_suff == NULL)
    die (EXIT_FAILURE, 0, _("invalid template %s, template must end by three or more X's"), quoteaf (template));

  size_t x_len = count_consecutive_X_s (x_suff, strlen (x_suff));
  if (x_len < 3)
    die (EXIT_FAILURE, 0, _("too few X's in template %s, template must end by three or more X's"), quoteaf (template));

  char *tmp_file = file_name_concat (tmp_dir, template, NULL);

  int fd = mktemp_len (tmp_file, 0, x_len, isdir, true);

  if (fd < 0 || close (fd) != 0)
    die (EXIT_FAILURE, errno, _("failed to create %s via template %s"),
         isdir ? _("directory") : _("file"), quoteaf (template));

  return tmp_file;
}

static bool
is_same_file (const char *src_name, const struct stat *src_sb,
              const char *dst_name, const struct stat *dst_sb,
              const struct cp_options *x)
{
  const struct stat *src_sb_link;
  const struct stat *dst_sb_link;
  struct stat tmp_dst_sb;
  struct stat tmp_src_sb;

  bool same_link;
  bool same = SAME_INODE (*src_sb, *dst_sb);

  /* FIXME: this should (at the very least) be moved into the following
     if-block.  More likely, it should be removed, because it inhibits
     making backups.  But removing it will result in a change in behavior
     that will probably have to be documented -- and tests will have to
     be updated.  */
  if (same && x->hard_link)
    return false;

  if (x->dereference == DEREF_NEVER)
    {
      same_link = same;

      /* If both the source and destination files are symlinks (and we will
         know this here IFF preserving symlinks), then it is usually ok
         when they are distinct.  */
      if (S_ISLNK (src_sb->st_mode) && S_ISLNK (dst_sb->st_mode))
        {
          bool sn = same_name (src_name, dst_name);
          if (!sn)
            {
              /* It is fine when we are making any type of backup.  */
              if (x->backup_type != no_backups)
                return false;

              /* Here we have two symlinks that are hard-linked together,
                 and we are not making backups.  In this unusual case, simply
                 returning true would lead to mv calling "rename(A, B)",
                 which would do nothing and return 0.  */
              if (same_link)
                return x->move_mode;
            }

          return sn;
        }

      src_sb_link = src_sb;
      dst_sb_link = dst_sb;
    }
  else
    {
      if (!same)
        return false;

      if (lstat (dst_name, &tmp_dst_sb) != 0
       || lstat (src_name, &tmp_src_sb) != 0)
        return false;

      src_sb_link = &tmp_src_sb;
      dst_sb_link = &tmp_dst_sb;

      same_link = SAME_INODE (*src_sb_link, *dst_sb_link);

      /* If both are symlinks, then it is ok, but only if the destination
         will be unlinked before being opened.  This is like the test
         above, but with the addition of the unlink_dest_before_opening
         conjunct because otherwise, with two symlinks to the same target,
         we'd end up truncating the source file.  */
      if (S_ISLNK (src_sb_link->st_mode) && S_ISLNK (dst_sb_link->st_mode)
       && x->unlink_dest_before_opening)
        return false;
    }

  /* The backup code ensures there is a copy, so it is usually ok to
     remove any destination file.  One exception is when both
     source and destination are the same directory entry.  In that
     case, moving the destination file aside (in making the backup)
     would also rename the source file and result in an error.  */
  if (x->backup_type != no_backups)
    {
      if (!same_link)
        {
          /* In copy mode when dereferencing symlinks, if the source is a
             symlink and the dest is not, then backing up the destination
             (moving it aside) would make it a dangling symlink, and the
             subsequent attempt to open it in copy_reg would fail with
             a misleading diagnostic.  Avoid that by returning zero in
             that case so the caller can make cp (or mv when it has to
             resort to reading the source file) fail now.  */

          /* FIXME-note: even with the following kludge, we can still provoke
             the offending diagnostic.  It is just a little harder to do :-)
             $ rm -f a b c; touch c; ln -s c b; ln -s b a; cp -b a b
             cp: cannot open 'a' for reading: No such file or directory
             That is misleading, since a subsequent 'ls' shows that 'a'
             is still there.
             One solution would be to open the source file *before* moving
             aside the destination, but that'd involve a big rewrite.  */
          if (!x->move_mode
           && x->dereference != DEREF_NEVER
           &&  S_ISLNK (src_sb_link->st_mode)
           && !S_ISLNK (dst_sb_link->st_mode))
            return true;

          return false;
        }

      /* FIXME: What about case insensitive file systems?  */
      return same_name (src_name, dst_name);
    }

#if 0
  /* FIXME: use or remove */

  /* If we are making a backup, we will detect the problem case in
     copy_reg because SRC_NAME will no longer exist.  Allowing
     the test to be deferred lets cp do some useful things.
     But when creating hardlinks and SRC_NAME is a symlink
     but DST_NAME is not we must test anyway.  */
  if (x->hard_link
   || !S_ISLNK (src_sb_link->st_mode)
   ||  S_ISLNK (dst_sb_link->st_mode))
    return false;

  if (x->dereference != DEREF_NEVER)
    return false;
#endif

  if (x->move_mode || x->unlink_dest_before_opening)
    {
      /* They may refer to the same file if we're in move mode and the
         target is a symlink.  That is ok, since we remove any existing
         destination file before opening it -- via 'rename' if they're on
         the same file system, via 'unlink (DST_NAME)' otherwise.  */
      if (S_ISLNK (dst_sb_link->st_mode))
        return false;

      /* It is not ok if they're distinct hard links to the same file as
         this causes a race condition and we may lose data in this case.  */
      if (same_link
       && dst_sb_link->st_nlink > 1
       && !same_name (src_name, dst_name))
        return x->move_mode;
    }

  /* If neither is a symlink, then it is ok as long as they are not
     hard links to the same file.  */
  if (!S_ISLNK (src_sb_link->st_mode) && !S_ISLNK (dst_sb_link->st_mode))
    {
      if (!SAME_INODE (*src_sb_link, *dst_sb_link))
        return false;

      /* If they are the same file, it is ok if we're making hard links.  */
      if (x->hard_link)
        return false;
    }

  /* At this point, it is normally an error (data loss) to move a symlink
     onto its referent, but in at least one narrow case, it is not:
     In move mode, when
     1) src is a symlink,
     2) dest has a link count of 2 or more and
     3) dest and the referent of src are not the same directory entry,
     then it is ok, since while we'll lose one of those hard links,
     src will still point to a remaining link.
     Note that technically, condition #3 obviates condition #2, but we
     retain the 1 < st_nlink condition because that means fewer invocations
     of the more expensive #3.

     Given this,
     $ touch f && ln f l && ln -s f s
     $ ls -og f l s
     -rw-------. 2  0 Jan  4 22:46 f
     -rw-------. 2  0 Jan  4 22:46 l
     lrwxrwxrwx. 1  1 Jan  4 22:46 s -> f
     this must fail: mv s f
     this must succeed: mv s l */
  if (x->move_mode
   && S_ISLNK (src_sb->st_mode)
   && dst_sb_link->st_nlink > 1)
    {
      char *abs_src = canonicalize_file_name (src_name);
      if (abs_src)
        {
          bool result = same_name (abs_src, dst_name);
          free (abs_src);
          return result;
        }
    }

  /* It is ok to recreate a destination symlink.  */
  if (x->symbolic_link && S_ISLNK (dst_sb_link->st_mode))
    return false;

  if (x->dereference == DEREF_NEVER)
    {
      if (!S_ISLNK (src_sb_link->st_mode))
        tmp_src_sb = *src_sb_link;
      else if (stat (src_name, &tmp_src_sb) != 0)
        return false;

      if (!S_ISLNK (dst_sb_link->st_mode))
        tmp_dst_sb = *dst_sb_link;
      else if (stat (dst_name, &tmp_dst_sb) != 0)
        return false;

      if (!SAME_INODE (tmp_src_sb, tmp_dst_sb))
        return false;

      if (x->hard_link)
        return false;
    }

  return true;
}

static bool
do_exchange (char *first_file, char *second_file, bool isdir, struct cp_options *x)
{
  struct stat first_file_sb;
  struct stat second_file_sb;

  if (stat (first_file, &first_file_sb) != 0)
    {
      error (0, errno, "%s", first_file);
      return false;
    }
  if (stat (second_file, &second_file_sb) != 0)
    {
      error (0, errno, "%s", second_file);
      return false;
    }

  if (is_same_file (first_file, &first_file_sb, second_file, &second_file_sb, x))
    {
      error (0, 0, _("%s and %s are the same file"),
             quoteaf_n (0, first_file), quoteaf_n (1, second_file));
      return false;
    }
  bool ok = true;

  char fmt[] = "xchg-%s-XXXXXXXXXXXX";

  char *template = xmalloc (sizeof (fmt) - 2 /* "%s" */ + strlen (first_file) + 1 /* "\0" */);
  sprintf (template, fmt, first_file);

  char *tmp_file = mktmp (template, isdir);

  ok &= do_move (first_file, tmp_file, x);
  ok &= do_move (second_file, first_file, x);
  ok &= do_move (tmp_file, second_file, x);

  free (tmp_file);
  free (template);

  return ok;
}

int
main (int argc, char **argv)
{
  struct cp_options x;
  bool ok = true;
  int shift = +1;
  int optc = -1;

  initialize_main (&argc, &argv);
  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  atexit (close_stdin);

  cp_option_init (&x);

  parse_long_options (argc, argv, PROGRAM_NAME, PACKAGE_NAME, Version, usage, AUTHORS,
                      (const char *) NULL);

  while ((optc = getopt_long (argc, argv, "s:", long_options, NULL)) != -1)
    switch (optc)
      {
      case 's':
        shift = xdectoimax (optarg, -argc + 1, +argc - 1, "", _("invalid shift"), 0);
        if (shift == 0)
          die (EXIT_FAILURE, 0, _("shift must be nonnull"));
        break;
      default:
        usage (EXIT_FAILURE);
      }

  argc -= optind;
  argv += optind;

  if (argc < 2)
    {
      error (0, 0, _("missing operand"));
      usage (EXIT_FAILURE);
    }

  struct stat dot_st;
  struct stat dot_dot_st;

  if (stat (".", &dot_st) != 0)
    die (EXIT_FAILURE, errno, ".");
  if (stat ("..", &dot_dot_st) != 0)
    die (EXIT_FAILURE, errno, "..");

  struct stat st;
  mode_t mode;

  for (int i = 0; i < argc; i++)
    {
      if (unlikely (stat (argv[i], &st) != 0))
        die (EXIT_FAILURE, errno, "%s", quotef (argv[i]));

      if (is_same_file (argv[i], &st, ".", &dot_st, &x)
       || is_same_file (argv[i], &st, "..", &dot_dot_st, &x))
        die (EXIT_FAILURE, 0, "cannot move %s", quotef (argv[i]));

      if (i > 0 && (mode & S_IFMT) != (st.st_mode & S_IFMT))
        die (EXIT_FAILURE, 0, "files must be of the same type");
      else if (i < argc - 1)
        mode = st.st_mode;
    }

  bool isdir = S_ISDIR (mode);

  /* Allocate space for remembering copied and created files.  */
  hash_init ();

  if (shift > 0)
    {
      for (int i = 0; i + shift < argc && ok; i++)
        {
          int sh = i + shift;
          ok &= do_exchange (argv[i], argv[sh], isdir, &x);
        }
    }
  else
    {
      for (int i = argc - 1; i - shift > 0 && ok; i--)
        {
          int sh = i - shift;
          ok &= do_exchange (argv[i], argv[sh], isdir, &x);
        }
    }

	forget_all ();

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
