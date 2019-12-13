/* Compute checksums of files or strings.
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

/* Written by Ulrich Drepper <drepper@gnu.ai.mit.edu>.
   SHA-3, MD6, recursive observing of directories support
   added by Sergey Sushilin.  */

#include <config.h>

#include <assert.h>
#include <fnmatch.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>

#include "system.h"

#include "areadlink.h"
#include "argmatch.h"
#include "canonicalize.h"
#include "dev-ino.h"
#include "dirname.h"
#include "filenamecat.h"
#include "hash.h"
#include "obstack.h"
#include "quote.h"
#include "xdectoint.h"
#include "xstrtol.h"

#if HASH_ALGO_BLAKE2B
# include "b2sum.h"
#endif

#if HASH_ALGO_MD2
# include "md2.h"
#endif

#if HASH_ALGO_MD4
# include "md4.h"
#endif

#if HASH_ALGO_MD5
# include "md5.h"
#endif

#if HASH_ALGO_MD6
# include "md6.h"
#endif

#if HASH_ALGO_SHA1
# include "sha1.h"
#endif

#if HASH_ALGO_SHA224 || HASH_ALGO_SHA256
# include "sha256.h"
#endif

#if HASH_ALGO_SHA384 || HASH_ALGO_SHA512
# include "sha512.h"
#endif

#if HASH_ALGO_SHA3
# include "sha3.h"
#endif

#include "die.h"
#include "error.h"
#include "fadvise.h"
#include "stdio--.h"
#include "xbinary-io.h"

/* The official name of this program (e.g., no 'g' prefix).  */
#if HASH_ALGO_BLAKE2B
# define PROGRAM_NAME       "b2sum"
# define DIGEST_TYPE_STRING "BLAKE2b"
# define DIGEST_STREAM      blake2b_stream
# define DIGEST_BITS        512
# define DIGEST_REFERENCE   "RFC 7693"
# define DIGEST_ALIGN       8
#elif HASH_ALGO_MD2
# define PROGRAM_NAME       "md2sum"
# define DIGEST_TYPE_STRING "MD2"
# define DIGEST_STREAM      md2_stream
# define DIGEST_BITS        128
# define DIGEST_REFERENCE   "RFC 1319"
# define DIGEST_ALIGN       4
#elif HASH_ALGO_MD4
# define PROGRAM_NAME       "md4sum"
# define DIGEST_TYPE_STRING "MD4"
# define DIGEST_STREAM      md4_stream
# define DIGEST_BITS        128
# define DIGEST_REFERENCE   "RFC 1186"
# define DIGEST_ALIGN       4
#elif HASH_ALGO_MD5
# define PROGRAM_NAME       "md5sum"
# define DIGEST_TYPE_STRING "MD5"
# define DIGEST_STREAM      md5_stream
# define DIGEST_BITS        128
# define DIGEST_REFERENCE   "RFC 1321"
# define DIGEST_ALIGN       4
#elif HASH_ALGO_MD6
# define PROGRAM_NAME       "md6sum"
# define DIGEST_TYPE_STRING "MD6"
# define DIGEST_STREAM      md6_stream
# define DIGEST_BITS        512
# define DIGEST_REFERENCE   "<https://groups.csail.mit.edu/cis/md6/docs/2009-04-15-md6-report.pdf>"
# define DIGEST_ALIGN       8
#elif HASH_ALGO_SHA1
# define PROGRAM_NAME       "sha1sum"
# define DIGEST_TYPE_STRING "SHA1"
# define DIGEST_STREAM      sha1_stream
# define DIGEST_BITS        160
# define DIGEST_REFERENCE   "FIPS-180-1"
# define DIGEST_ALIGN       4
#elif HASH_ALGO_SHA224
# define PROGRAM_NAME       "sha224sum"
# define DIGEST_TYPE_STRING "SHA224"
# define DIGEST_STREAM      sha224_stream
# define DIGEST_BITS        224
# define DIGEST_REFERENCE   "RFC 3874"
# define DIGEST_ALIGN       4
#elif HASH_ALGO_SHA256
# define PROGRAM_NAME       "sha256sum"
# define DIGEST_TYPE_STRING "SHA256"
# define DIGEST_STREAM      sha256_stream
# define DIGEST_BITS        256
# define DIGEST_REFERENCE   "FIPS-180-2"
# define DIGEST_ALIGN       4
#elif HASH_ALGO_SHA384
# define PROGRAM_NAME       "sha384sum"
# define DIGEST_TYPE_STRING "SHA384"
# define DIGEST_STREAM      sha384_stream
# define DIGEST_BITS        384
# define DIGEST_REFERENCE   "FIPS-180-2"
# define DIGEST_ALIGN       8
#elif HASH_ALGO_SHA512
# define PROGRAM_NAME       "sha512sum"
# define DIGEST_TYPE_STRING "SHA512"
# define DIGEST_STREAM      sha512_stream
# define DIGEST_BITS        512
# define DIGEST_REFERENCE   "FIPS-180-2"
# define DIGEST_ALIGN       8
#elif HASH_ALGO_SHA3
# define PROGRAM_NAME       "sha3sum"
# define DIGEST_TYPE_STRING "SHA3"
# define DIGEST_STREAM      sha3_stream
# define DIGEST_BITS        512
# define DIGEST_REFERENCE   "FIPS-202"
# define DIGEST_ALIGN       8
#else
# error "Cannot decide which hash algorithm to compile."
#endif

#if HASH_ALGO_BLAKE2B
# define AUTHORS \
  proper_name ("Padraig Brady"), \
  proper_name ("Samuel Neves")
#else
# define AUTHORS \
  proper_name ("Ulrich Drepper"), \
  proper_name ("Scott Miller"), \
  proper_name ("David Madore")
#endif

#define obstack_chunk_alloc malloc
#define obstack_chunk_free  free

/* Unix-based readdir implementations have historically returned a dirent.d_ino
   value that is sometimes not equal to the stat-obtained st_ino value for
   that same entry.  This error occurs for a readdir entry that refers
   to a mount point.  readdir's error is to return the inode number of
   the underlying directory -- one that typically cannot be stat'ed, as
   long as a file system is mounted on that directory.  RELIABLE_D_INO
   encapsulates whether we can use the more efficient approach of relying
   on readdir-supplied d_ino values, or whether we must incur the cost of
   calling stat or lstat to obtain each guaranteed-valid inode number.  */
#if !defined(READDIR_LIES_ABOUT_MOUNTPOINT_D_INO)
# define READDIR_LIES_ABOUT_MOUNTPOINT_D_INO 1
#endif

#if READDIR_LIES_ABOUT_MOUNTPOINT_D_INO
# define RELIABLE_D_INO(dp) NOT_AN_INODE_NUMBER
#else
# define RELIABLE_D_INO(dp) D_INO (dp)
#endif

/* The minimum length of a valid digest line.  This length does
   not include any newline character at the end of a line.  */
#if HASH_HAVE_VARIABLE_SIZE && !HASH_ALGO_SHA3
# define MIN_DIGEST_LINE_LENGTH \
  (1   /* The minimum length of hexadecimal message digest (with '-l 8').  */ \
   + 2 /* Blank and binary indicator.  */ \
   + 1 /* Minimum filename length.  */)
#elif HASH_ALGO_SHA3
# define MIN_DIGEST_LINE_LENGTH \
  (28  /* The minimum length of hexadecimal message digest (with '-l 224').  */ \
   + 2 /* Blank and binary indicator.  */ \
   + 1 /* Minimum filename length.  */)
#else
#define DIGEST_HEX_BYTES (DIGEST_BITS / 4)
# define MIN_DIGEST_LINE_LENGTH \
  (DIGEST_HEX_BYTES /* Length of hexadecimal message digest.  */ \
   + 2 /* Blank and binary indicator.  */ \
   + 1 /* Minimum filename length.  */)
#endif
#define DIGEST_BIN_BYTES (DIGEST_BITS / 8)

/* True if any of the files read were the standard input.  */
static bool have_read_stdin;

/* The minimum length of a valid checksum line for the selected algorithm.  */
static size_t min_digest_line_length;

/* Set to the length of a digest hex string for the selected algorithm.  */
static size_t digest_hex_bytes;

/* With --check, do not generate any output.
   The exit code indicates success or failure.  */
static bool status_only = false;

/* With --check, print a message to standard error warning about each
   improperly formatted checksum line.  */
static bool warn = false;

/* With --check, ignore missing files.  */
static bool ignore_missing = false;

/* With --check, suppress the "OK" printed for each verified file.  */
static bool quiet = false;

/* With --check, exit with a non-zero return code if any line is
   improperly formatted.  */
static bool strict = false;

/* Whether a BSD reversed format checksum is detected.  */
static int bsd_reversed = -1;

static bool prefix_tag = false;

/* Line delimiter.  */
static unsigned char delim = '\n';

/* With -r, true means when a directory is found, print hash sums of its
   contents.  */
static bool recursive = false;

/* Which files to ignore.  */
static enum
{
  /* Ignore files whose names start with '.', and files specified by
     --ignore.  */
  IGNORE_DEFAULT,

  /* Ignore only files specified by --ignore.  */
  IGNORE_MINIMAL
} ignore_mode;

/* A linked list of shell-style globbing patterns.  If a non-argument
   file name matches any of these patterns, it is ignored.
   Controlled by -I.  Multiple -I options accumulate.
   The -B option adds '*~' and '.*~' to this list.  */
struct ignore_pattern
{
  const char *pattern;
  struct ignore_pattern *next;
};

static struct ignore_pattern *ignore_patterns;

/* Similar to IGNORE_PATTERNS, except that -a causes this
   variable itself to be ignored.  */
static struct ignore_pattern *hide_patterns;

#if HASH_HAVE_VARIABLE_SIZE
static uintmax_t digest_length;

static const char *const algorithm_in_string =
#if HASH_ALGO_BLAKE2B
  "blake2b"
#elif HASH_ALGO_MD6
  "md6"
#elif HASH_ALGO_SHA3
  "sha3"
#endif
  ;
static const char *const algorithm_out_string =
#if HASH_ALGO_BLAKE2B
  "BLAKE2b"
#elif HASH_ALGO_MD6
  "MD6"
#elif HASH_ALGO_SHA3
  "SHA3"
#endif
  ;

/* NOTE: BLAKE2b, SHA3 and MD6 have same maximum length,
   but if will be added new hash function, then this const
   must be corrected if it is neccessary.  */
/* Max length for BLAKE2b, MD6 and SHA3.  */
static uintmax_t digest_max_len = 512 / 8;
#endif /* HASH_HAVE_VARIABLE_SIZE */

/* For long options that have no equivalent short option, use a
   non-character as a pseudo short option, starting with CHAR_MAX + 1.  */
enum
{
  IGNORE_MISSING_OPTION = CHAR_MAX + 1,
  STATUS_OPTION,
  QUIET_OPTION,
  STRICT_OPTION,
  TAG_OPTION
};

static const struct option long_options[] =
{
  {"all", no_argument, NULL, 'a'},
  {"binary", no_argument, NULL, 'b'},
  {"check", no_argument, NULL, 'c'},
  {"hide", required_argument, NULL, 'H'},
  {"ignore", required_argument, NULL, 'I'},
  {"ignore-backups", no_argument, NULL, 'B'},
  {"ignore-missing", no_argument, NULL, IGNORE_MISSING_OPTION},
#if HASH_HAVE_VARIABLE_SIZE
  {"length", required_argument, NULL, 'l'},
#endif
  {"quiet", no_argument, NULL, QUIET_OPTION},
  {"recursive", no_argument, NULL, 'r'},
  {"status", no_argument, NULL, STATUS_OPTION},
  {"strict", no_argument, NULL, STRICT_OPTION},
  {"tag", no_argument, NULL, TAG_OPTION},
  {"text", no_argument, NULL, 't'},
  {"warn", no_argument, NULL, 'w'},
  {"zero", no_argument, NULL, 'z'},
  {NULL, 0, NULL, '\0'}
};

enum filetype
{
  unknown,
  regular_file,
  directory,
  arg_directory
};

struct fileinfo
{
  char *name;
  /* For symbolic link, name of the file linked to, otherwise zero.  */
  char *linkname;
  struct stat stat;
  enum filetype filetype;
  bool stat_ok;
};

/* Initial size of hash table.
   Most hierarchies are likely to be shallower than this.  */
#define INITIAL_TABLE_SIZE 32

/* The set of 'active' directories, from the current command-line argument
   to the level in the hierarchy at which files are being listed.
   A directory is represented by its device and inode numbers (struct dev_ino).
   A directory is added to this set when ls begins listing it or its
   entries, and it is removed from the set just after ls has finished
   processing it.  This set is used solely to detect loops, e.g., with
   mkdir loop; cd loop; ln -s ../loop sub; md5sum -r ./ */
static Hash_table *active_dir_set;

#define LOOP_DETECT (active_dir_set != NULL)

/* The table of files in the current directory:

   'cwd_file' is a vector of 'struct fileinfo', one per file.
   'cwd_n_alloc' is the number of elements space has been allocated for.
   'cwd_n_used' is the number actually in use.  */

/* Address of block containing the files that are described.  */
static struct fileinfo *cwd_file;

/* Length of block that 'cwd_file' points to, measured in files.  */
static size_t cwd_n_alloc;

/* Index of first unused slot in 'cwd_file'.  */
static size_t cwd_n_used;

/* Record of one pending directory waiting to be listed.  */
struct pending
{
  char *name;
  /* If the directory is actually the file pointed to by a symbolic link we
     were told to list, 'realname' will contain the name of the symbolic
     link, otherwise zero.  */
  char *realname;
  bool command_line_arg;
  struct pending *next;
};

static struct pending *pending_dirs;

/* With -r, this stack is used to help detect directory cycles.
   The device/inode pairs on this stack mirror the pairs in the
   active_dir_set hash table.  */
static struct obstack dev_ino_obstack;

/* Push a pair onto the device/inode stack.  */
static void
dev_ino_push (dev_t dev, ino_t ino)
{
  void *vdi;
  struct dev_ino *di;
  unsigned int dev_ino_size = sizeof (struct dev_ino);

  obstack_blank (&dev_ino_obstack, dev_ino_size);
  vdi = obstack_next_free (&dev_ino_obstack);
  di = vdi;
  di--;
  di->st_dev = dev;
  di->st_ino = ino;
}
/* Pop a dev/ino struct off the global dev_ino_obstack
   and return that struct.  */
static struct dev_ino
dev_ino_pop (void)
{
  void *vdi;
  struct dev_ino *di;
  unsigned int dev_ino_size = sizeof (struct dev_ino);
  assert (dev_ino_size <= obstack_object_size (&dev_ino_obstack));

  obstack_blank_fast (&dev_ino_obstack, -(int) dev_ino_size);
  vdi = obstack_next_free (&dev_ino_obstack);
  di = vdi;

  return *di;
}

static size_t
dev_ino_hash (const void *x, size_t table_size)
{
  const struct dev_ino *p = x;
  return (size_t) p->st_ino % table_size;
}

static bool
dev_ino_compare (const void *x, const void *y)
{
  const struct dev_ino *a = x;
  const struct dev_ino *b = y;
  return SAME_INODE (*a, *b);
}
static void
dev_ino_free (void *x)
{
  free (x);
}

/* Add the device/inode pair (P->st_dev/P->st_ino) to the set of
   active directories.  Return true if there is already a matching
   entry in the table.  */
static bool
visit_dir (dev_t device, ino_t inode)
{
  struct dev_ino *ent;
  struct dev_ino *ent_from_table;
  bool found_match;

  ent = xmalloc (sizeof (*ent));
  ent->st_dev = device;
  ent->st_ino = inode;

  /* Attempt to insert this entry into the table.  */
  ent_from_table = hash_insert (active_dir_set, ent);

  if (ent_from_table == NULL)
    /* Insertion failed due to lack of memory.  */
    xalloc_die ();

  found_match = (ent_from_table != ent);
  if (found_match)
    /* ent was not inserted, so free it.  */
    free (ent);

  return found_match;
}

static void
free_pending_ent (struct pending *p)
{
  free (p->name);
  free (p->realname);
  free (p);
}

/* Enter and remove entries in the table 'cwd_file'.  */
static void
free_ent (struct fileinfo *f)
{
  free (f->name);
  free (f->linkname);
}

/* Empty the table of files.  */
static void
clear_files (void)
{
  for (size_t i = 0; i < cwd_n_used; i++)
    free_ent (cwd_file + i);
  cwd_n_used = 0;
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
  return ((ignore_mode != IGNORE_MINIMAL
           && file[0] == '.'
           && (ignore_mode == IGNORE_DEFAULT || file[1 + (file[1] == '.' ? 1 : 0)] == '\0'))
          || (ignore_mode == IGNORE_DEFAULT && patterns_match (hide_patterns, file))
          || patterns_match (ignore_patterns, file));
}

static struct stat dot_st;
static struct stat dot_dot_st;

/* Return true if the filename's inode same as '.' or '..' inode.  */
static bool
is_dot_or_dotdot (const char *dirname, struct stat st)
{
  if (unlikely (stat (dirname, &st) != 0))
    die (EXIT_FAILURE, errno, "%s", quotef (dirname));

  return (st.st_dev == dot_st.st_dev     && st.st_ino == dot_st.st_ino)
      || (st.st_dev == dot_dot_st.st_dev && st.st_ino == dot_dot_st.st_ino);
}

/* Return true if the last component of NAME is '.'
   This is so we do not try to recurse on '././././. ...' */
static bool
basename_is_dot (const char *name)
{
  if (*name == '.')
    {
      name++;
      return (*name == '\0' || (ISSLASH (*name) && *(name + 1) == '\0'));
    }
  else
    return false;
}

/* Put DIRNAME/NAME into DEST, handling '.' and '/' properly.  */
/* FIXME: maybe remove this function someday.  See about using a
   non-malloc'ing version of file_name_concat.  */
static void __nonnull ((1, 2, 3))
attach (char *dest, const char *dirname, const char *name, bool force)
{
  if (*name == '/' || *dirname == '\0')
    {
      strcpy (dest, name);
      return;
    }

  size_t i = 0;

  /* Copy dirname if it is not "." or if we were asked to do this.  */
  if (force || !basename_is_dot (dirname))
    {
      memcpy (dest, dirname, (i = strlen (dirname)));
      /* Add '/' if 'dirname' does not already end with it.  */
      if (dirname[i - 1] != '/')
        dest[i++] = '/';
    }

  strcpy (dest + i, name);
}

/* Return true if F refers to a directory.  */
static bool _GL_ATTRIBUTE_CONST
is_directory (const struct fileinfo *f)
{
  return f->filetype == directory
      || f->filetype == arg_directory;
}

/* Request that the directory named NAME have its contents listed later.
   If REALNAME is nonzero, it will be used instead of NAME when the
   directory name is printed.  This allows symbolic links to directories
   to be treated as regular directories but still be listed under their
   real names.  NAME == NULL is used to insert a marker entry for the
   directory named in REALNAME.
   If NAME is non-NULL, we use its dev/ino information to save
   a call to stat -- when doing a recursive (-r) traversal.
   COMMAND_LINE_ARG means this directory was mentioned on the command line.  */
static void
queue_directory (const char *name, const char *realname, bool command_line_arg)
{
  struct pending *new = xmalloc (sizeof (*new));
  new->realname = realname != NULL ? xstrdup (realname) : NULL;
  new->name = name != NULL ? xstrdup (name) : NULL;
  new->command_line_arg = command_line_arg;
  new->next = pending_dirs;
  pending_dirs = new;
}

/* Remove any entries from CWD_FILE that are for directories,
   and queue them to be listed as directories instead.
   DIRNAME is the prefix to prepend to each dirname
   to make it correct relative to md5sum's working dir;
   if it is null, no prefix is needed and "." and ".." should not be ignored.
   If COMMAND_LINE_ARG is true, this directory was mentioned at the top level,
   This is desirable when processing directories recursively.  */
static void
extract_dirs_from_files (const char *dirname, bool command_line_arg)
{
  bool ignore_dot_and_dot_dot = (dirname != NULL);

  if (dirname != NULL && LOOP_DETECT)
    /* Insert a marker entry first.  When we dequeue this marker entry,
       we will know that DIRNAME has been processed and may be removed
       from the set of active directories.  */
    queue_directory (NULL, dirname, false);

  /* Queue the directories last one first, because queueing reverses the
     order.  */
  for (size_t i = cwd_n_used; i != 0; i--)
    {
      struct fileinfo *f = cwd_file + i;

      if (is_directory (f)
          && (!ignore_dot_and_dot_dot || !is_dot_or_dotdot (f->name, f->stat)))
        {
          if (dirname == NULL || f->name[0] == '/')
            queue_directory (f->name, f->linkname, command_line_arg);
          else
            {
              char *name = file_name_concat (dirname, f->name, NULL);
              queue_directory (name, f->linkname, command_line_arg);
              free (name);
            }
          if (f->filetype == arg_directory)
            {
              free_ent (f);
              cwd_n_used--;
            }
        }
    }
}

/* Add a file to the current table of files.
   Verify that the file exists, and print an error message if it does not.  */
static void __nonnull ((1, 5))
gobble_file (const char *name, enum filetype type, ino_t inode,
             bool command_line_arg, const char *dirname)
{
  if (!command_line_arg && file_ignored (name))
    return;

  /* An inode value prior to gobble_file necessarily came from readdir,
     which is not used for command line arguments.  */
  assert (!command_line_arg || inode == NOT_AN_INODE_NUMBER);

  if (unlikely (cwd_n_used == cwd_n_alloc))
    {
      cwd_file = xnrealloc (cwd_file, cwd_n_alloc, 2 * sizeof (*cwd_file));
      cwd_n_alloc *= 2;
    }

  struct fileinfo *f = cwd_file + cwd_n_used;
  memset (f, '\0', sizeof (*f));
  f->stat.st_ino = inode;
  f->filetype = type;

  if (unlikely (STREQ (name, "-") && *dirname == '\0'))
    {
      assert (command_line_arg);
      f->name = xstrdup ("-");
      f->filetype = regular_file;
      f->stat_ok = true;
      cwd_n_used++;
      return;
    }

  /* Absolute name of this file.  */
  char *full_name;

  if (*name == '/' || *dirname == '\0')
    {
      full_name = xmalloc (strlen (name) + 1);
      strcpy (full_name, name);
    }
  else
    {
      full_name = xmalloc (strlen (name) + strlen (dirname) + 2);
      attach (full_name, dirname, name, false);
    }

  if (unlikely (stat (full_name, &f->stat) != 0))
    {
      if (lstat (full_name, &f->stat) == 0 && S_ISLNK (f->stat.st_mode))
        {
          error (0, errno, _("bad symlink %s"), quoteaf (full_name));
          free (full_name);
          return;
        }
      else
        error (0, errno, _("cannot access %s"), quoteaf (full_name));

      if (!command_line_arg)
        {
          f->name = full_name;
          cwd_n_used++;
        }
      else
        free (full_name);
      return;
    }

  f->stat_ok = true;

  if (S_ISDIR (f->stat.st_mode))
    {
      if (!recursive)
        {
          error (0, EISDIR, "%s", quotef (full_name));
          free (full_name);
          return;
        }
      if (command_line_arg)
        f->filetype = arg_directory;
      else
        f->filetype = directory;
    }
  else
    f->filetype = regular_file;

  f->name = full_name;
  cwd_n_used++;
}

/* The set of signals that are caught.  */
static sigset_t caught_signals;

/* If nonzero, the value of the pending fatal signal.  */
static volatile sig_atomic_t interrupt_signal;

/* A count of the number of pending stop signals that have been received.  */
static volatile sig_atomic_t stop_signal_count;

/* Process any pending signals.  If signals are caught, this function
   should be called periodically.  Ideally there should never be an
   unbounded amount of time when signals are not being processed.
   Signal handling can restore the default colors, so callers must
   immediately change colors after invoking this function.  */
static void
process_signals (void)
{
  while (interrupt_signal != 0 || stop_signal_count != 0)
    {
      int sig;
      int stops;
      sigset_t oldset;

      fflush (stdout);

      sigprocmask (SIG_BLOCK, &caught_signals, &oldset);

      /* Reload interrupt_signal and stop_signal_count, in case a new
         signal was handled before sigprocmask took effect.  */
      sig = interrupt_signal;
      stops = stop_signal_count;

      /* SIGTSTP is special, since the application can receive that signal
         more than once.  In this case, do not set the signal handler to the
         default.  Instead, just raise the uncatchable SIGSTOP.  */
      if (stops != 0)
        {
          stop_signal_count = stops - 1;
          sig = SIGSTOP;
        }
      else
        signal (sig, SIG_DFL);

      /* Exit or suspend the program.  */
      raise (sig);
      sigprocmask (SIG_SETMASK, &oldset, NULL);

      /* If execution reaches here, then the program has been
         continued (after being suspended).  */
    }
}

/* Advise the user about invalid usages like "md5sum -foo" if the file
   "-foo" exists, assuming ARGC and ARGV are as with 'main'.  */
static void
diagnose_leading_hyphen (int argc, char **argv)
{
  /* OPTIND is unreliable, so iterate through the arguments looking
     for a file name that looks like an option.  */

  struct stat st;

  for (int i = 1; i < argc; i++)
    {
      const char *arg = *(argv + i);
      if (*arg == '-' && *(arg + 1) != '\0' && lstat (arg, &st) == 0)
        {
          fprintf (stderr,
                   _("Try '%s ./%s' to get a digest of the file %s.\n"),
                   argv[0],
                   quotearg_n_style (1, shell_escape_quoting_style, arg),
                   quoteaf (arg));
        }
    }
}

void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    emit_try_help ();
  else
    {
      printf (_("\
Usage: %s [OPTION]... [FILE]...\n\
"), program_name);

#if !HASH_HAVE_VARIABLE_SIZE
      printf (_("\
Print or check %s (%i-bit) checksums.\n\
"), DIGEST_TYPE_STRING, DIGEST_BITS);
#endif

      emit_stdin_note ();

      fputs (_("\
  -a, --all            do not ignore entries starting with .\n\
"), stdout);

#if O_BINARY
      fputs (_("\
\n\
  -b, --binary         read in binary mode (default unless reading tty stdin)\n\
"), stdout);
#else
      fputs (_("\
\n\
  -b, --binary         read in binary mode\n\
"), stdout);
#endif

      printf (_("\
  -c, --check          read %s sums from the FILEs and check them\n\
"), DIGEST_TYPE_STRING);

#if HASH_HAVE_VARIABLE_SIZE && !HASH_ALGO_SHA3
      fputs (_("\
  -l, --length         digest length in bits; must not exceed the maximum for\n\
                       the "DIGEST_TYPE_STRING" algorithm and must be a multiple of 8\n\
"), stdout);
#elif HASH_ALGO_SHA3
      fputs (_("\
  -l, --length         digest length in bits; must not exceed the maximum for\n\
                       the SHA-3 algorithm and must be equal either 224, 256, 384 or 512\n\
"), stdout);
#endif

      fputs (_("\
      --hide=PATTERN   do not list implied entries matching shell PATTERN\
\n\
                         (overridden by -a)\n\
"), stdout);

      fputs (_("\
      --tag            create a BSD-style checksum\n\
"), stdout);

#if O_BINARY
      fputs (_("\
  -t, --text           read in text mode (default if reading tty stdin)\n\
"), stdout);
#else
      fputs (_("\
  -t, --text           read in text mode (default)\n\
"), stdout);
#endif

      fputs (_("\
  -z, --zero           end each output line with NUL, not newline,\n\
                       and disable file name escaping\n\
"), stdout);
      fputs (_("\
  -r, --recursive      create checksums of directory's contents\n\
"), stdout);
      fputs (_("\
\n\
The following five options are useful only when verifying checksums:\n\
      --ignore-missing do not fail or report status for missing files\n\
      --quiet          do not print OK for each successfully verified file\n\
      --status         do not output anything, status code shows success\n\
      --strict         exit non-zero for improperly formatted checksum lines\n\
  -w, --warn           warn about improperly formatted checksum lines\n\
\n\
"), stdout);

      fputs (HELP_OPTION_DESCRIPTION, stdout);
      fputs (VERSION_OPTION_DESCRIPTION, stdout);

      fputs (_("\
\n\
The sums are computed as described in "DIGEST_REFERENCE".  When checking, the input\n\
should be a former output of this program.  The default mode is to print a\n\
line with checksum, a space, a character indicating input mode ('*' for binary,\n\
' ' for text or where binary is insignificant), and name for each FILE.\n\
\n\
Note: There is no difference between binary mode and text mode on GNU systems.\n\
"), stdout);

      emit_ancillary_info (PROGRAM_NAME);
    }

  exit (status);
}

#define ISWHITE(c) ((c) == ' ' || (c) == '\t')

/* Given a file name, S of length S_LEN, that is not NUL-terminated,
   modify it in place, performing the equivalent of this sed substitution:
   's/\\n/\n/g;s/\\\\/\\/g' i.e., replacing each "\\n" string with a newline
   and each "\\\\" with a single backslash, NUL-terminate it and return S.
   If S is not a valid escaped file name, i.e., if it ends with an odd number
   of backslashes or if it contains a backslash followed by anything other
   than "n" or another backslash, return NULL.  */
static char *
filename_unescape (char *s, size_t s_len)
{
  char *dst = s;

  for (size_t i = 0; i < s_len; i++)
    {
      switch (s[i])
        {
        case '\\':
          if (i == s_len - 1)
            {
              /* File name ends with an unescaped backslash: invalid.  */
              return NULL;
            }
          i++;
          switch (s[i])
            {
            case 'n':
              *dst++ = '\n';
              break;
            case '\\':
              *dst++ = '\\';
              break;
            default:
              /* Only '\' or 'n' may follow a backslash.  */
              return NULL;
            }
          break;
        case '\0':
          /* The file name may not contain a NUL.  */
          return NULL;
        default:
          *dst++ = s[i];
          break;
        }
    }
  if (dst < s + s_len)
    *dst = '\0';

  return s;
}

/* Return true if S is a NUL-terminated string of DIGEST_HEX_BYTES hex digits.
   Otherwise, return false.  */
static bool _GL_ATTRIBUTE_PURE
hex_digits (const unsigned char *s)
{
  size_t i;
  for (i = 0; i < digest_hex_bytes; i++)
    if (!isxdigit (s[i]))
      return false;
  return s[i] == '\0';
}

/* Split the checksum string S (of length S_LEN) from a BSD 'md5' or
   'sha1' command into two parts: a hexadecimal digest, and the file
   name.  S is modified.  Return true if successful.  */
static bool
bsd_split_3 (char *s, size_t s_len, unsigned char **hex_digest,
             char **file_name, bool escaped_filename)
{
  if (s_len == 0)
    return false;

  /* Find end of filename.  */
  size_t i = s_len - 1;
  while (i != 0 && s[i] != ')')
    i--;

  if (s[i] != ')')
    return false;

  *file_name = s;

  if (escaped_filename && filename_unescape (s, i) == NULL)
    return false;

  s[i++] = '\0';

  while (ISWHITE (s[i]))
    i++;

  if (s[i] != '=')
    return false;

  i++;

  while (ISWHITE (s[i]))
    i++;

  *hex_digest = (unsigned char *) &s[i];

  return hex_digits (*hex_digest);
}

/* Split the string S (of length S_LEN) into three parts:
   a hexadecimal digest, binary flag, and the file name.
   S is modified.  Return true if successful.  */
static bool
split_3 (char *s, size_t s_len, unsigned char **hex_digest,
         int *binary, char **file_name)
{
  bool escaped_filename = false;

  size_t i = 0;
  while (ISWHITE (s[i]))
    i++;

  if (s[i] == '\\')
    {
      i++;
      escaped_filename = true;
    }

  /* Check for BSD-style checksum line.  */
  size_t algo_name_len = strlen (DIGEST_TYPE_STRING);
  if (strncmp (s + i, DIGEST_TYPE_STRING, algo_name_len) == 0)
    {
      i += algo_name_len;

#if HASH_HAVE_VARIABLE_SIZE
      /* Terminate and match algorithm name.  */
      const char *algo_name = &s[i - algo_name_len];
      /* Skip algorithm variants.  */
      while (s[i] != '\0' && !ISWHITE (s[i]) && s[i] != '-' && s[i] != '(')
        i++;
      bool length_specified = s[i] == '-';
      bool openssl_format = s[i] == '('; /* And no length_specified.  */
      s[i++] = '\0';
      ptrdiff_t algo = argmatch (algo_name, (const char *const []) {algorithm_out_string, NULL}, NULL, 0);
      if (algo < 0)
        return false;

      if (openssl_format)
        s[--i] = '(';

      if (length_specified)
        {
          unsigned long int tmp_ulong;
          if (xstrtoul (s + i, NULL, 0, &tmp_ulong, NULL) == LONGINT_OK
              && tmp_ulong > 0
              && tmp_ulong <= digest_max_len * 8
              && tmp_ulong % 8 == 0)
            digest_length = tmp_ulong;
          else
            return false;

          while (ISDIGIT (s[i]))
            i++;
        }
      else
        digest_length = digest_max_len * 8;

      digest_hex_bytes = digest_length / 4;
#endif

      if (s[i] == ' ')
        i++;
      if (s[i] == '(')
        {
          i++;
          *binary = 0;
          return bsd_split_3 (s + i, s_len - i, hex_digest,
                              file_name, escaped_filename);
        }
      return false;
    }

  /* Ignore this line if it is too short.
     Each line must have at least 'min_digest_line_length - 1' (or one more, if
     the first is a backslash) more characters to contain correct message digest
     information.  */
  if (s_len - i < min_digest_line_length + (s[i] == '\\'))
    return false;

  *hex_digest = (unsigned char *) &s[i];

#if HASH_HAVE_VARIABLE_SIZE
  /* Auto determine length.  */
  const unsigned char *hp = *hex_digest;
  digest_hex_bytes = 0;
  while (isxdigit (*hp++))
    digest_hex_bytes++;
  if (digest_hex_bytes < 2
      || digest_hex_bytes % 2
      || digest_max_len * 2 < digest_hex_bytes)
    return false;
  digest_length = digest_hex_bytes * 4;
#endif

  /* The first field has to be the n-character hexadecimal
     representation of the message digest.  If it is not followed
     immediately by a white space it is an error.  */
  i += digest_hex_bytes;
  if (!ISWHITE (s[i]))
    return false;

  s[i++] = '\0';

  if (!hex_digits (*hex_digest))
    return false;

  /* If "bsd reversed" format detected.  */
  if ((s_len - i == 1) || (s[i] != ' ' && s[i] != '*'))
    {
      /* Do not allow mixing bsd and standard formats,
         to minimize security issues with attackers
         renaming files with leading spaces.
         This assumes that with bsd format checksums
         that the first file name does not have
         a leading ' ' or '*'.  */
      if (bsd_reversed == 0)
        return false;
      bsd_reversed = 1;
    }
  else if (bsd_reversed != 1)
    {
      bsd_reversed = 0;
      *binary = (s[i++] == '*');
    }

  /* All characters between the type indicator and end of line are
     significant -- that includes leading and trailing white space.  */
  *file_name = &s[i];

  if (escaped_filename)
    return filename_unescape (&s[i], s_len - i) != NULL;

  return true;
}

/* If ESCAPE is true, then translate each NEWLINE byte to the string, "\\n",
   and each backslash to "\\\\".  */
static void
print_filename (const char *file, bool escape)
{
  if (!escape)
    {
      fputs (file, stdout);
      return;
    }

  for (size_t i = 0; file[i] != '\0'; i++)
    {
      switch (file[i])
        {
        case '\n':
          fputs ("\\n", stdout);
          break;
        case '\\':
          fputs ("\\\\", stdout);
          break;
        default:
          putchar (file[i]);
          break;
        }
    }
}

static void
print_digest (char *file, int file_is_binary, unsigned char *bin_buffer)
{
  /* We do not really need to escape, and hence detect, the '\\'
     char, and not doing so should be both forwards and backwards
     compatible, since only escaped lines would have a '\\' char at
     the start.  However just in case users are directly comparing
     against old (hashed) outputs, in the presence of files
     containing '\\' characters, we decided to not simplify the
     output in this case.  */
  bool needs_escape = (strchr (file, '\\') != NULL || strchr (file, '\n') != NULL) && delim == '\n';

  if (prefix_tag)
    {
      if (needs_escape)
        putchar ('\\');

#if HASH_HAVE_VARIABLE_SIZE
      fputs (algorithm_out_string, stdout);
      if (digest_length < digest_max_len * 8)
        printf ("-%"PRIuMAX, digest_length);
#else
      fputs (DIGEST_TYPE_STRING, stdout);
#endif

      fputs (" (", stdout);
      print_filename (file, needs_escape);
      fputs (") = ", stdout);
    }

  /* Output a leading backslash if the file name contains
     a newline or backslash.  */
  if (!prefix_tag && needs_escape)
    putchar ('\\');

  for (size_t i = 0; i < (digest_hex_bytes / 2); i++)
    printf ("%02x", bin_buffer[i]);

  if (!prefix_tag)
    {
      putchar (' ');
      putchar (file_is_binary != 0 ? '*' : ' ');
      print_filename (file, needs_escape);
    }

  putchar (delim);
}

static bool digest_file (char *dirname, int *binary, unsigned char *bin_buffer, bool *missing);
static void digest_directory (char *dirname, int *binary, unsigned char *bin_buffer, bool *missing);

static void
digest_current_files (int *binary, unsigned char *bin_buffer, bool *missing)
{
  for (size_t i = 0; i < cwd_n_used; i++)
    {
      char *file = cwd_file[i].name;
      if (cwd_file[i].filetype == directory || cwd_file[i].filetype == arg_directory)
        {
          if (!recursive)
            error (0, EISDIR, "%s", quotef (file));
          else
            {
              char full_dirname[PATH_MAX];
              if (getcwd (full_dirname, sizeof (full_dirname) - strlen (file) - 1 /* '/' */ - 1 /* '\0' */) == NULL)
                {
                  error (0, errno, "%s", quotef (file));
                  continue;
                }

              attach (full_dirname, file, "", true);
              digest_directory (full_dirname, binary, bin_buffer, missing);
            }
        }
      else
        if (digest_file (file, binary, bin_buffer, missing))
          print_digest (file, *binary, bin_buffer);
    }

  clear_files ();
}

/* An interface to the function, DIGEST_STREAM.
   Operate on FILENAME (it may be "-").

   *BINARY indicates whether the file is binary.  BINARY < 0 means it
   depends on whether binary mode makes any difference and the file is
   a terminal; in that case, clear *BINARY if the file was treated as
   text because it was a terminal.

   Put the checksum in *BIN_BUFFER, which must be properly aligned.
   Put true in *MISSING if the file can not be opened due to ENOENT.
   Return true if successful.  */
static bool
digest_file (char *filename, int *binary _GL_UNUSED, unsigned char *bin_buffer, bool *missing)
{
  FILE *fp;
  int err;
  bool is_stdin = STREQ (filename, "-");

  *missing = false;

  if (is_stdin)
    {
      have_read_stdin = true;
      fp = stdin;
#if O_BINARY
      if (*binary != 0)
        {
          if (*binary < 0)
            *binary = !isatty (STDIN_FILENO) ? 1 : 0;
          if (*binary != 0)
            xset_binary_mode (STDIN_FILENO, O_BINARY);
        }
#endif
    }
  else
    {
#if O_BINARY
      fp = fopen (filename, (*binary != 0 ? "rb" : "r"));
#else
      fp = fopen (filename, "r");
#endif
      if (unlikely (fp == NULL))
        {
          if (ignore_missing && errno == ENOENT)
            {
              *missing = true;
              return true;
            }
          error (0, errno, "%s", quotef (filename));
          return false;
        }
    }

  fadvise (fp, FADVISE_SEQUENTIAL);

#if HASH_HAVE_VARIABLE_SIZE
  err = DIGEST_STREAM (fp, bin_buffer, digest_length / 8);
#else
  err = DIGEST_STREAM (fp, bin_buffer);
#endif

  if (err != 0)
    {
      error (0, errno, "%s", quotef (filename));
      if (!is_stdin)
        if (fclose (fp) != 0)
          error (0, errno, "%s", quotef (filename));
      return false;
    }

  if (!is_stdin && fclose (fp) != 0)
    {
      error (0, errno, "%s", quotef (filename));
      return false;
    }

  return true;
}

static void
digest_directory (char *dirname, int *binary, unsigned char *bin_buffer, bool *missing)
{
  DIR *dirp;
  struct dirent *ent;

  errno = 0;
  dirp = opendir (dirname);
  if (unlikely (dirp == NULL))
    {
      if (ignore_missing && errno == ENOENT)
        *missing = true;
      else
        error (0, errno, _("cannot open directory %s"), quoteaf (dirname));
      return;
    }

  if (LOOP_DETECT)
    {
      struct stat dir_stat;
      int fd = dirfd (dirp);

      /* If dirfd failed, endure the overhead of using stat.  */
      if ((fd >= 0
             ? fstat (fd, &dir_stat)
             :  stat (dirname, &dir_stat)) < 0)
        {
          error (0, errno, _("cannot determine device and inode of %s"), quoteaf (dirname));
          if (closedir (dirp) != 0)
            error (0, errno, _("closing directory %s"), quoteaf (dirname));
          return;
        }

      /* If we have already visited this device/inode pair, warn that
         we have found a loop, and do not process this directory.  */
      if (visit_dir (dir_stat.st_dev, dir_stat.st_ino))
        {
          error (0, 0, _("%s: not listing already-listed directory"), quotef (dirname));
          if (closedir (dirp) != 0)
            error (0, errno, _("closing directory %s"), quoteaf (dirname));
          return;
        }

      dev_ino_push (dir_stat.st_dev, dir_stat.st_ino);
    }

  /* We have to left it here to avoid warnings like 'do not listing already-listed directory'.  */
  clear_files ();

  /* Read the directory entries, and insert the subfiles into the 'cwd_file' table.  */
  while (true)
    {
      /* Set errno to zero so we can distinguish between a readdir failure
         and when readdir simply finds that there are no more entries.  */
      errno = 0;
      ent = readdir_ignoring_dot_and_dotdot (dirp);
      if (ent != NULL)
        {
          if (!file_ignored (ent->d_name))
            {
              enum filetype type;

#if HAVE_STRUCT_DIRENT_D_TYPE
              if (ent->d_type == DT_DIR)
                type = directory;
              else
                type = regular_file;
#else
              {
                struct stat ent_stat;
                if (stat (ent->d_name, &ent_stat) != 0) /* At this line is two reasons why using d_type is better.  */
                  {
                    error (0, errno, _("cannot stat %s"), quoteaf (ent->d_name));
                    break;
                  }
                if (S_ISDIR (ent_st.st_mode))
                  type = directory;
                else
                  type = regular_file;
              }
#endif

              gobble_file (ent->d_name, type,
                           RELIABLE_D_INO (ent),
                           false, dirname);

              /* In this narrow case, print out hash sums right away, so
                 md5sum uses constant memory while processing the entries
                 of this directory.  Useful when there are many (millions)
                 of entries in a directory.  */
              digest_current_files (binary, bin_buffer, missing);
            }
        }
      else if (errno != 0)
        {
          error (0, errno, _("reading directory %s"), quoteaf (dirname));
          if (errno != EOVERFLOW)
            break;
        }
      else
        break;

      /* When processing a very large directory, and since we have inhibited
         interrupts, this loop would take so long that md5sum would be annoyingly
         uninterruptible.  This ensures that it handles signals promptly.  */
      process_signals ();
    }

  if (closedir (dirp) != 0)
    {
      error (0, errno, _("closing directory %s"), quoteaf (dirname));
      /* Do not return; print whatever we got.  */
    }

  /* If any member files are subdirectories, perhaps they should have their
     contents printed digest rather than being mentioned here as files.  */
  if (recursive)
    extract_dirs_from_files (dirname, false);

  if (cwd_n_used != 0)
    digest_current_files (binary, bin_buffer, missing);
}

static bool
digest_check (char *checkfile_name)
{
  FILE *checkfile_stream;
  uintmax_t n_misformatted_lines = 0;
  uintmax_t n_improperly_formatted_lines = 0;
  uintmax_t n_mismatched_checksums = 0;
  uintmax_t n_open_or_read_failures = 0;
  bool properly_formatted_lines = false;
  bool matched_checksums = false;
  unsigned char bin_buffer_unaligned[DIGEST_BIN_BYTES + DIGEST_ALIGN];
  /* Make sure bin_buffer is properly aligned.  */
  unsigned char *bin_buffer = ptr_align (bin_buffer_unaligned, DIGEST_ALIGN);
  uintmax_t line_number;
  char *line;
  size_t line_chars_allocated;
  bool is_stdin = STREQ (checkfile_name, "-");

  if (is_stdin)
    {
      have_read_stdin = true;
      checkfile_name = _("standard input");
      checkfile_stream = stdin;
    }
  else
    {
      checkfile_stream = fopen (checkfile_name, "r");
      if (unlikely (checkfile_stream == NULL))
        {
          error (0, errno, "%s", quotef (checkfile_name));
          return false;
        }
    }

  line_number = 0;
  line = NULL;
  line_chars_allocated = 0;
  do
    {
      char *filename IF_LINT ( = NULL);
      int binary;
      unsigned char *hex_digest IF_LINT ( = NULL);
      ssize_t line_length;

      line_number++;
      if (line_number == 0)
        die (EXIT_FAILURE, 0, _("%s: too many checksum lines"),
             quotef (checkfile_name));

      line_length = getline (&line, &line_chars_allocated, checkfile_stream);
      if (line_length <= 0)
        break;

      /* Ignore comment lines, which begin with a '#' character.  */
      if (line[0] == '#')
        continue;

      /* Remove any trailing newline.  */
      if (line[line_length - 1] == '\n')
        line[--line_length] = '\0';

      if (!(split_3 (line, line_length, &hex_digest, &binary, &filename)
       && !(is_stdin && STREQ (filename, "-"))))
        {
          n_misformatted_lines++;

          if (warn)
            error (0, 0, _("%s: %"PRIuMAX": improperly formatted %s checksum line"),
                   quotef (checkfile_name), line_number, DIGEST_TYPE_STRING);

          n_improperly_formatted_lines++;
        }
      else
        {
          static const char bin2hex[] =
          {
            '0', '1', '2', '3',
            '4', '5', '6', '7',
            '8', '9', 'a', 'b',
            'c', 'd', 'e', 'f'
          };
          bool ok;
          bool missing;
          /* Only escape in the edge case producing multiple lines,
             to ease automatic processing of status output.  */
          bool needs_escape = !status_only && strchr (filename, '\n') != NULL;

          properly_formatted_lines = true;

          ok = digest_file (filename, &binary, bin_buffer, &missing);

          if (!ok)
            {
              n_open_or_read_failures++;
              if (!status_only)
                {
                  if (needs_escape)
                    putchar ('\\');
                  print_filename (filename, needs_escape);
                  printf (": %s\n", _("FAILED open or read"));
                }
            }
          else if (ignore_missing && missing)
            {
              /* Ignore missing files with --ignore-missing.  */
              ;
            }
          else
            {
              size_t digest_bin_bytes = digest_hex_bytes / 2;
              size_t cnt;

              /* Compare generated binary number with text representation
                 in check file.  Ignore case of hex digits.  */
              for (cnt = 0; cnt < digest_bin_bytes; cnt++)
                {
                  if (tolower (hex_digest[2 * cnt + 0]) != (bin2hex[bin_buffer[cnt] >> 0x04])
                  ||  tolower (hex_digest[2 * cnt + 1]) != (bin2hex[bin_buffer[cnt] &  0x0F]))
                    break;
                }
              if (cnt != digest_bin_bytes)
                n_mismatched_checksums++;
              else
                matched_checksums = true;

              if (!status_only)
                {
                  if (cnt != digest_bin_bytes || !quiet)
                    {
                      if (needs_escape)
                        putchar ('\\');
                      print_filename (filename, needs_escape);
                    }

                  if (cnt != digest_bin_bytes)
                    printf (": %s\n", _("FAILED"));
                  else if (!quiet)
                    printf (": %s\n", _("OK"));
                }
            }
        }
    }
  while (!feof (checkfile_stream) && !ferror (checkfile_stream));

  free (line);

  if (ferror (checkfile_stream))
    {
      error (0, 0, _("%s: read error"), quotef (checkfile_name));
      return false;
    }

  if (!is_stdin && fclose (checkfile_stream) != 0)
    {
      error (0, errno, "%s", quotef (checkfile_name));
      return false;
    }

  if (properly_formatted_lines == 0)
    /* Warn if no tests are found.  */
    error (0, 0, _("%s: no properly formatted %s checksum lines found"),
           quotef (checkfile_name), DIGEST_TYPE_STRING);
  else
    {
      if (!status_only)
        {
          if (n_misformatted_lines != 0)
            error (0, 0,
                   (S_
                    ("WARNING: %"PRIuMAX" line is improperly formatted",
                     "WARNING: %"PRIuMAX" lines are improperly formatted",
                     select_plural (n_misformatted_lines))),
                   n_misformatted_lines);

          if (n_open_or_read_failures != 0)
            error (0, 0,
                   (S_
                    ("WARNING: %"PRIuMAX" listed file could not be read",
                     "WARNING: %"PRIuMAX" listed files could not be read",
                     select_plural (n_open_or_read_failures))),
                   n_open_or_read_failures);

          if (n_mismatched_checksums != 0)
            error (0, 0,
                   (S_
                    ("WARNING: %"PRIuMAX" computed checksum did NOT match",
                     "WARNING: %"PRIuMAX" computed checksums did NOT match",
                     select_plural (n_mismatched_checksums))),
                   n_mismatched_checksums);

          if (ignore_missing && !matched_checksums)
            error (0, 0, _("%s: no file was verified"),
                   quotef (checkfile_name));
        }
    }

  return (properly_formatted_lines
       && matched_checksums
       && n_mismatched_checksums == 0
       && n_open_or_read_failures == 0
       && (!strict || n_improperly_formatted_lines == 0));
}

int
main (int argc, char **argv)
{
  unsigned char bin_buffer_unaligned[DIGEST_BIN_BYTES + DIGEST_ALIGN];
  /* Make sure bin_buffer is properly aligned.  */
  unsigned char *bin_buffer = ptr_align (bin_buffer_unaligned, DIGEST_ALIGN);
  bool do_check = false;
  int optc = -1;
  bool ok = true;
  int binary = -1;
  bool missing = false;
  pending_dirs = NULL;
  struct pending *thispend;
  ignore_mode = IGNORE_DEFAULT;
  ignore_patterns = NULL;
  hide_patterns = NULL;

  /* Setting values of global variables.  */
  initialize_main (&argc, &argv);
  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  atexit (close_stdout);

  /* Line buffer stdout to ensure lines are written atomically and immediately
     so that processes running in parallel do not intersperse their output.  */
  if (setvbuf (stdout, NULL, _IOLBF, 0) != 0)
    die (EXIT_FAILURE, errno, _("could not set buffering of stdout to mode _IOLBF"));

  parse_long_options (argc, argv, PROGRAM_NAME, PACKAGE_NAME, Version, usage, AUTHORS,
                      (const char *) NULL);

#if HASH_HAVE_VARIABLE_SIZE
  const char *digest_length_str = "";
  const char *short_options = "abcl:rtwzBHI:R";
#else
  const char *short_options = "abcrtwzBHI:R";
#endif

  while ((optc = getopt_long (argc, argv, short_options, long_options, NULL)) != -1)
    switch (optc)
      {
      case 'a':
        ignore_mode = IGNORE_MINIMAL;
        break;
      case 'b':
        binary = 1;
        break;
      case 'c':
        do_check = true;
        break;
#if HASH_HAVE_VARIABLE_SIZE
      case 'l':
        digest_length_str = optarg;
        digest_length = xdectoumax (optarg, 0, UINTMAX_MAX, "", _("invalid length"), 0);

# if HASH_ALGO_SHA3
        if (digest_length != 224 && digest_length != 256
         && digest_length != 384 && digest_length != 512)
          {
            error (0, 0, _("invalid length: %s"), quote (digest_length_str));
            die (EXIT_FAILURE, 0, _("valid digest lengths are 224, 256, 384 and 512 bits"));
          }
# else
        if (digest_length % 8 != 0)
          {
            error (0, 0, _("invalid length: %s"), quote (digest_length_str));
            die (EXIT_FAILURE, 0, _("length is not a multiple of 8"));
          }
# endif

        break;
#endif
      case STATUS_OPTION:
        status_only = true;
        warn = false;
        quiet = false;
        break;
      case 't':
        binary = 0;
        break;
      case 'w':
        status_only = false;
        warn = true;
        quiet = false;
        break;
      case IGNORE_MISSING_OPTION:
        ignore_missing = true;
        break;
      case 'r':
        recursive = true;
        break;
      case QUIET_OPTION:
        status_only = false;
        warn = false;
        quiet = true;
        break;
      case STRICT_OPTION:
        strict = true;
        break;
      case TAG_OPTION:
        prefix_tag = true;
        binary = 1;
        break;
      case 'z':
        delim = '\0';
        break;
      case 'B':
        add_ignore_pattern ("*~");
        add_ignore_pattern (".*~");
        break;
      case 'H':
        {
          struct ignore_pattern *hide = xmalloc (sizeof (*hide));
          hide->pattern = optarg;
          hide->next = hide_patterns;
          hide_patterns = hide;
        }
        break;
      case 'I':
        add_ignore_pattern (optarg);
        break;
      default:
        diagnose_leading_hyphen (argc, argv);
        usage (EXIT_FAILURE);
      }

  min_digest_line_length = MIN_DIGEST_LINE_LENGTH;
#if HASH_HAVE_VARIABLE_SIZE
  if (unlikely (digest_length > digest_max_len * 8))
    {
      error (0, 0, _("invalid length: %s"), quote (digest_length_str));
      die (EXIT_FAILURE, 0,
           _("maximum digest length for %s is %"PRIuMAX" bits"),
           quote (algorithm_in_string),
           digest_max_len * 8);
    }
  if (digest_length == 0 && !do_check)
    digest_length = digest_max_len * 8;
  digest_hex_bytes = digest_length / 4;
#else
  digest_hex_bytes = DIGEST_HEX_BYTES;
#endif

  if (prefix_tag && !binary)
    {
      /* This could be supported in a backwards compatible way
         by prefixing the output line with a space in text mode.
         However that's invasive enough that it was agreed to
         not support this mode with --tag, as --text use cases
         are adequately supported by the default output format.  */
      error (0, 0, _("--tag does not support --text mode"));
      usage (EXIT_FAILURE);
    }
  if (delim != '\n' && do_check)
    {
      error (0, 0, _("the --zero option is not supported when "
                     "verifying checksums"));
      usage (EXIT_FAILURE);
    }
  if (prefix_tag && do_check)
    {
      error (0, 0, _("the --tag option is meaningless when "
                     "verifying checksums"));
      usage (EXIT_FAILURE);
    }
  if (binary >= 0 && do_check)
    {
      error (0, 0, _("the --binary and --text options are meaningless when "
                     "verifying checksums"));
      usage (EXIT_FAILURE);
    }
  if (ignore_missing && !do_check)
    {
      error (0, 0, _("the --ignore-missing option is meaningful only when "
                     "verifying checksums"));
      usage (EXIT_FAILURE);
    }
  if (status_only && !do_check)
    {
      error (0, 0, _("the --status option is meaningful only when "
                     "verifying checksums"));
      usage (EXIT_FAILURE);
    }
  if (warn && !do_check)
    {
      error (0, 0, _("the --warn option is meaningful only when "
                     "verifying checksums"));
      usage (EXIT_FAILURE);
    }
  if (quiet && !do_check)
    {
      error (0, 0, _("the --quiet option is meaningful only when "
                     "verifying checksums"));
      usage (EXIT_FAILURE);
    }
  if (strict && !do_check)
    {
      error (0, 0, _("the --strict option is meaningful only when "
                     "verifying checksums"));
      usage (EXIT_FAILURE);
    }

#if !O_BINARY
  if (binary < 0)
    binary = 0;
#endif

  if (do_check)
    {
      for (int i = optind; i < argc; i++)
        ok &= digest_check (argv[i]);
      return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

  /* When using -r, initialize a data structure we will use to
     detect any directory cycles.  */
  if (recursive)
    {
      active_dir_set = hash_initialize (INITIAL_TABLE_SIZE,
                                        NULL,
                                        dev_ino_hash,
                                        dev_ino_compare,
                                        dev_ino_free);
      if (active_dir_set == NULL)
        xalloc_die ();

      obstack_init (&dev_ino_obstack);
    }

  if (recursive)
    {
      if (stat (".", &dot_st) != 0)
        die (EXIT_FAILURE, errno, ".");
      if (stat ("..", &dot_dot_st) != 0)
        die (EXIT_FAILURE, errno, "..");
    }

  cwd_n_alloc = 128;
  cwd_file = xnmalloc (cwd_n_alloc, sizeof (*cwd_file));
  cwd_n_used = 0;

  if (optind == argc)
    gobble_file ("-", regular_file, NOT_AN_INODE_NUMBER, true, "");
  else
    for (int i = optind; i < argc; i++)
      gobble_file (argv[i], unknown, NOT_AN_INODE_NUMBER, true, "");

  if (cwd_n_used != 0)
    {
      extract_dirs_from_files (NULL, true);
      /* 'cwd_n_used' might be zero now.  */
    }

  int file_is_binary = binary;

  /* In the following if/else blocks, it is sufficient to test 'pending_dirs'
     (and not pending_dirs->name) because there may be no markers in the queue
     at this point.  A marker may be enqueued when extract_dirs_from_files is
     called with a non-empty string or via digest_directory.  */
  if (cwd_n_used != 0)
    digest_current_files (&file_is_binary, bin_buffer, &missing);

  while (pending_dirs != NULL)
    {
      thispend = pending_dirs;
      pending_dirs = pending_dirs->next;

      if (LOOP_DETECT)
        {
          if (thispend->name == NULL)
            {
              /* thispend->name == NULL means this is a marker entry
                 indicating we have finished processing the directory.
                 Use its dev/ino numbers to remove the corresponding
                 entry from the active_dir_set hash table.  */
              struct dev_ino di = dev_ino_pop ();
              struct dev_ino *found = hash_delete (active_dir_set, &di);
              /* ASSERT_MATCHING_DEV_INO (thispend->realname, di); */
              assert (found != NULL);
              dev_ino_free (found);
              free_pending_ent (thispend);
              continue;
            }
        }

      digest_directory (thispend->name, &file_is_binary, bin_buffer, &missing);

      free_pending_ent (thispend);
    }

  if (unlikely (have_read_stdin && fclose (stdin) != 0))
    die (EXIT_FAILURE, errno, _("standard input"));

  free (cwd_file);

  if (active_dir_set != NULL)
    {
      obstack_free (&dev_ino_obstack, NULL);
      assert (hash_get_n_entries (active_dir_set) == 0);
      hash_free (active_dir_set);
    }

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
