#ifndef _FORCE_LINK_H
#define _FORCE_LINK_H 1

extern int force_linkat (int, const char *, int, const char *, int, bool, int);
extern int force_symlinkat (const char *, int, const char *, bool, int);

#endif /* _FORCE_LINK_H */
