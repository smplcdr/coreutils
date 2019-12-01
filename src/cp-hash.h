
#ifndef _CP_HASH_H
#define _CP_HASH_H 1

void hash_init (void);
void forget_all (void);
void forget_created (ino_t ino, dev_t dev);
char *remember_copied (const char *node, ino_t ino, dev_t dev);
char *src_to_dest_lookup (ino_t ino, dev_t dev);

#endif
