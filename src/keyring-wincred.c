
/* Avoid warning about empty compilation unit. */
void keyring_wincred_dummy(void) { }

#ifdef _WIN32

#define R_NO_REMAP 1

#include "oskeyring.h"
#include "cleancall.h"

#include <Rinternals.h>
#include <R_ext/Rdynload.h>

#include <windows.h>
#include <wincred.h>

#include <string.h>

void oskeyring_cred_free(void *buffer) {
  CredFree(buffer);
}

void keyring_wincred_handle_status(const char *func, BOOL status) {
  if (status == FALSE) {
    DWORD errorcode = GetLastError();
    LPVOID lpMsgBuf;
    char *msg;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorcode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    msg = R_alloc(1, strlen(lpMsgBuf) + 1);
    strcpy(msg, lpMsgBuf);
    LocalFree(lpMsgBuf);

    Rf_error("Windows credential store error in '%s': %s", func, msg);
  }
}

PCREDENTIAL_ATTRIBUTEW from_attributes(SEXP attr, SEXP nms) {
  DWORD i, cnt = Rf_length(attr);
  PCREDENTIAL_ATTRIBUTEW ptr = (PCREDENTIAL_ATTRIBUTEW)
    R_alloc(sizeof(struct _CREDENTIAL_ATTRIBUTEW), cnt);
  for (i = 0; i < cnt; i++) {
    ptr[i].Keyword = (wchar_t*) RAW(VECTOR_ELT(nms, i));
    ptr[i].Flags = 0;
    ptr[i].ValueSize = Rf_length(VECTOR_ELT(attr, i));
    ptr[i].Value = RAW(VECTOR_ELT(attr, i));
  }

  return ptr;
}

SEXP oskeyring_windows_write(SEXP item, SEXP preserve) {
  const char *type = CHAR(STRING_ELT(list_elt(item, "type"), 0));
  CREDENTIALW cred = { 0 };
  cred.Flags = 0;
  if (!strcmp(type, "generic")) {
    cred.Type = CRED_TYPE_GENERIC;
  } else {
    Rf_error("Invalid credential type: `%s`", type);
  }
  cred.TargetName = (wchar_t*) RAW(list_elt(item, "target_name"));
  SEXP comment = list_elt(item, "comment");
  if (!Rf_isNull(comment)) cred.Comment = (wchar_t*) RAW(comment);
  SEXP credential_blob = list_elt(item, "credential_blob");
  cred.CredentialBlobSize = Rf_length(credential_blob);
  cred.CredentialBlob =
    Rf_isNull(credential_blob) ? NULL : RAW(credential_blob);
  const char *persist = CHAR(STRING_ELT(list_elt(item, "persist"), 0));
  if (!strcmp(persist, "session")) {
    cred.Persist = CRED_PERSIST_SESSION;
  } else if (!strcmp(persist, "local_machine")) {
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
  } else if (!strcmp(persist, "enterprise")) {
    cred.Persist = CRED_PERSIST_ENTERPRISE;
  } else {
    Rf_error("Invalid persist parameter: `%s`", persist);
  }
  SEXP attributes = list_elt(item, "attributes");
  SEXP attribute_names = list_elt(item, "attribute_names");
  cred.AttributeCount = Rf_length(attributes);
  cred.Attributes = from_attributes(attributes, attribute_names);
  SEXP target_alias = list_elt(item, "target_alias");
  if (!Rf_isNull(target_alias)) {
    cred.TargetAlias = (wchar_t*) RAW(target_alias);
  }
  SEXP username = list_elt(item, "username");
  if (!Rf_isNull(username)) cred.UserName = (wchar_t*) RAW(username);

  DWORD flags = LOGICAL(preserve)[0] ? CRED_PRESERVE_CREDENTIAL_BLOB : 0;
  BOOL status = CredWriteW(&cred, flags);

  keyring_wincred_handle_status("write", status);

  return R_NilValue;
}

SEXP as_raw_wcs(wchar_t *wcs) {
  if (wcs == NULL) return R_NilValue;
  DWORD len = wcslen(wcs) * sizeof(wchar_t);
  SEXP ret = PROTECT(Rf_allocVector(RAWSXP, len));
  memcpy(RAW(ret), wcs, len);
  UNPROTECT(1);
  return ret;
}

SEXP as_raw_len(LPBYTE buffer, DWORD len) {
  SEXP ret = PROTECT(Rf_allocVector(RAWSXP, len));
  memcpy(RAW(ret), buffer, len);
  UNPROTECT(1);
  return ret;
}

SEXP as_time(FILETIME wt) {
  long long ll, secs, nsecs;
  ll = ((LONGLONG) wt.dwHighDateTime) << 32;
  ll += wt.dwLowDateTime - 116444736000000000LL;
  secs = ll / 10000000;
  nsecs = ll % 10000000;
  double t = (double) secs + ((double) nsecs) / 10000000;

  SEXP rt = PROTECT(Rf_ScalarReal(t));
  SEXP class = PROTECT(Rf_allocVector(STRSXP, 2));
  SET_STRING_ELT(class, 0, Rf_mkCharCE("POSIXct", CE_UTF8));
  SET_STRING_ELT(class, 1, Rf_mkCharCE("POSIXt", CE_UTF8));
  Rf_setAttrib(rt, R_ClassSymbol, class);
  UNPROTECT(2);
  return rt;
}

SEXP as_attributes(PCREDENTIAL_ATTRIBUTEW attr, DWORD cnt) {
  SEXP ret = PROTECT(Rf_allocVector(VECSXP, cnt));
  DWORD i;

  for (i = 0; i < cnt; i++) {
    SET_VECTOR_ELT(ret, i, Rf_allocVector(RAWSXP, attr[i].ValueSize));
    memcpy(RAW(VECTOR_ELT(ret, i)), attr[i].Value, attr[i].ValueSize);
  }

  UNPROTECT(1);
  return ret;
}

SEXP as_attribute_names(PCREDENTIAL_ATTRIBUTEW attr, DWORD cnt) {
  SEXP nms = PROTECT(Rf_allocVector(VECSXP, cnt));
  DWORD i;

  for (i = 0; i < cnt; i++) {
    SET_VECTOR_ELT(nms, i, as_raw_wcs(attr[i].Keyword));
  }

  UNPROTECT(1);
  return nms;
}

SEXP as_cred(CREDENTIALW *cred) {
  const char *nms[] = {
    "type", "target_name", "credential_blob", "comment", "persist",
    "attributes", "attribute_names", "target_alias", "username",
    "last_written", "flags", "" };

  SEXP ret = PROTECT(Rf_mkNamed(VECSXP, nms));
  switch (cred->Type) {
  case CRED_TYPE_GENERIC:
    SET_VECTOR_ELT(ret, 0, Rf_mkString("generic"));
    break;
  case CRED_TYPE_DOMAIN_PASSWORD:
    SET_VECTOR_ELT(ret, 0, Rf_mkString("domain_password"));
    break;
  case CRED_TYPE_DOMAIN_CERTIFICATE:
    SET_VECTOR_ELT(ret, 0, Rf_mkString("domain_certificate"));
    break;
  case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
    SET_VECTOR_ELT(ret, 0, Rf_mkString("domain_visible_password"));
    break;
  default:
    Rf_error("Unknown credential type: %i", (int) cred->Type);
  }

  SET_VECTOR_ELT(ret, 1, as_raw_wcs(cred->TargetName));
  SET_VECTOR_ELT(ret, 2,
    as_raw_len(cred->CredentialBlob, cred->CredentialBlobSize));
  SET_VECTOR_ELT(ret, 3, as_raw_wcs(cred->Comment));
  switch (cred->Persist) {
    case CRED_PERSIST_SESSION:
      SET_VECTOR_ELT(ret, 4, Rf_mkString("session"));
      break;
    case CRED_PERSIST_LOCAL_MACHINE:
      SET_VECTOR_ELT(ret, 4, Rf_mkString("local_machine"));
      break;
    case CRED_PERSIST_ENTERPRISE:
      SET_VECTOR_ELT(ret, 4, Rf_mkString("enterprise"));
      break;
    default:
      Rf_error("Unknown persistence type: %i", (int) cred->Persist);
  }
  SET_VECTOR_ELT(ret, 5,
                 as_attributes(cred->Attributes, cred->AttributeCount));
  SET_VECTOR_ELT(ret, 6,
                 as_attribute_names(cred->Attributes, cred->AttributeCount));
  SET_VECTOR_ELT(ret, 7, as_raw_wcs(cred->TargetAlias));
  SET_VECTOR_ELT(ret, 8, as_raw_wcs(cred->UserName));
  SET_VECTOR_ELT(ret, 9, as_time(cred->LastWritten));
  SET_VECTOR_ELT(ret, 10, Rf_ScalarInteger(cred->Flags));

  Rf_setAttrib(ret, R_ClassSymbol, Rf_mkString("oskeyring_windows_item"));

  UNPROTECT(1);
  return ret;
}

static DWORD from_type(SEXP type) {
  const char *ctype = CHAR(STRING_ELT(type, 0));
  if (!strcmp(ctype, "generic")) {
    return CRED_TYPE_GENERIC;
  } else if (!strcmp(ctype, "domain_password")) {
    return CRED_TYPE_DOMAIN_PASSWORD;
  } else if (!strcmp(ctype, "domain_certificate")) {
    return CRED_TYPE_DOMAIN_CERTIFICATE;
  } else if (!strcmp(ctype, "domain_visible_password")) {
    return CRED_TYPE_DOMAIN_VISIBLE_PASSWORD;
  } else {
    Rf_error("Invalid credential type: `%s`", ctype);
    return 0;
  }
}

SEXP oskeyring_windows_read(SEXP target_name, SEXP type) {
  CREDENTIALW *cred = 0;
  DWORD wtype = from_type(type);
  BOOL status = CredReadW((wchar_t*) RAW(target_name), wtype, 0, &cred);
  keyring_wincred_handle_status("read", status);
  r_call_on_exit((finalizer_t) oskeyring_cred_free, (void*) cred);

  return as_cred(cred);
}

SEXP oskeyring_windows_delete(SEXP target_name, SEXP type) {
  const wchar_t *ctarget = (wchar_t*) RAW(target_name);
  DWORD wtype = from_type(type);
  BOOL status = CredDeleteW(ctarget, wtype, 0);
  keyring_wincred_handle_status("delete", status);

  return R_NilValue;
}

SEXP oskeyring_windows_enumerate(SEXP filter, SEXP all) {
  const wchar_t *cfilter =
    Rf_isNull(filter) ? NULL : (wchar_t*) RAW(filter);
  DWORD flags = LOGICAL(all)[0] ? 0x1 : 0;
  DWORD count;
  PCREDENTIALW *creds = NULL;

  BOOL status = CredEnumerateW(cfilter, flags, &count, &creds);
  DWORD errorcode = status ? 0 : GetLastError();

  /* If there are no keys, then an error is thrown. But for us this is
   a normal result, and we just return an empty table. */
  if (status == FALSE && errorcode == ERROR_NOT_FOUND) {
    return Rf_allocVector(VECSXP, 0);
  }

  if (status == FALSE) {
    keyring_wincred_handle_status("enumerate", status);
    return R_NilValue;
  }

  r_call_on_exit((finalizer_t) oskeyring_cred_free, creds);

  size_t i, num = (size_t) count;
  SEXP result = PROTECT(Rf_allocVector(VECSXP, num));
  for (i = 0; i < count; i++) {
    SET_VECTOR_ELT(result, i, as_cred(creds[i]));
  }

  UNPROTECT(1);
  return result;
}

SEXP keyring_wincred_enumerate(SEXP filter) {
  const char *cfilter = CHAR(STRING_ELT(filter, 0));

  DWORD count;
  PCREDENTIAL *creds = NULL;

  BOOL status = CredEnumerate(cfilter, /* Flags = */ 0, &count, &creds);
  DWORD errorcode = status ? 0 : GetLastError();

  /* If there are no keys, then an error is thrown. But for us this is
     a normal result, and we just return an empty table. */
  if (status == FALSE && errorcode == ERROR_NOT_FOUND) {
    SEXP result = PROTECT(Rf_allocVector(STRSXP, 0));
    UNPROTECT(1);
    return result;

  } else if (status == FALSE) {
    if (creds != NULL) CredFree(creds);
    keyring_wincred_handle_status("list", status);
    return R_NilValue;

  } else {
    size_t i, num = (size_t) count;
    SEXP result = PROTECT(Rf_allocVector(STRSXP, num));
    for (i = 0; i < count; i++) {
      SET_STRING_ELT(result, i, Rf_mkChar(creds[i]->TargetName));
    }
    CredFree(creds);

    UNPROTECT(1);
    return result;
  }
}

#define REGISTER(method, args) \
{ #method, (DL_FUNC) &method, args }

static const R_CallMethodDef callMethods[]  = {
  REGISTER(oskeyring_windows_write,     2),
  REGISTER(oskeyring_windows_read,      2),
  REGISTER(oskeyring_windows_delete,    2),
  REGISTER(oskeyring_windows_enumerate, 2),

  CLEANCALL_METHOD_RECORD,

  { NULL, NULL, 0 }
};

void R_init_oskeyring(DllInfo *dll) {
  R_registerRoutines(dll, NULL, callMethods, NULL, NULL);
  R_useDynamicSymbols(dll, FALSE);
  R_forceSymbols(dll, TRUE);
  cleancall_init();
}

#endif // _WIN32
