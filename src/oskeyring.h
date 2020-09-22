
#ifndef OSKEYRING_H
#define OSKEYRING_H

#define R_NO_REMAP 1

#include <R.h>
#include <Rinternals.h>

SEXP list_elt(SEXP list, const char *str);

#endif
