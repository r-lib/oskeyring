
/* Avoid warning about empty compilation unit. */
void keyring_secret_service_dummy() { }

#ifndef _WIN32
#ifndef __APPLE__


#define R_NO_REMAP 1

#include "oskeyring.h"
#include "cleancall.h"

#include <Rinternals.h>
#include <R_ext/Rdynload.h>

#define REGISTER(method, args) \
{ #method, (DL_FUNC) &method, args }

static const R_CallMethodDef callMethods[]  = {
  CLEANCALL_METHOD_RECORD,

  { NULL, NULL, 0 }
};

void R_init_oskeyring(DllInfo *dll) {
  R_registerRoutines(dll, NULL, callMethods, NULL, NULL);
  R_useDynamicSymbols(dll, FALSE);
  R_forceSymbols(dll, TRUE);
  cleancall_init();
}

#endif // __APPLE__
#endif // _WIN32
