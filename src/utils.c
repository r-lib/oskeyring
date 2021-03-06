
#include "oskeyring.h"

SEXP list_elt(SEXP list, const char *str) {
  SEXP nms = Rf_getAttrib(list, R_NamesSymbol);

  for (int i = 0; i < Rf_length(list); i++)
    if (!strcmp(CHAR(STRING_ELT(nms, i)), str)) {
      return VECTOR_ELT(list, i);
    }

  Rf_error("Cannot find element `%s` in list", str);
  return R_NilValue;
}
