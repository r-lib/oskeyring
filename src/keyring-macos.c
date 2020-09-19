
/* Avoid warning about empty compilation unit. */
void oskeyring_macos_dummy() { }

#ifdef __APPLE__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <R.h>
#include <R_ext/Rdynload.h>
#include <Rinternals.h>

#include <sys/param.h>
#include <string.h>

#include "oskeyring.h"
#include "cleancall.h"

// ------------------------------------------------------------------------
// Conversion from SEXP to CF
// ------------------------------------------------------------------------

CFStringRef cf_chr1(SEXP x) {
  const char *cx = CHAR(STRING_ELT(x, 0));
  CFStringRef cs = CFStringCreateWithCString(NULL, cx, kCFStringEncodingUTF8);
  r_call_on_exit((finalizer_t) CFRelease, (void*) cs);
  return cs;
}

CFBooleanRef cf_lgl1(SEXP x) {
  if (LOGICAL(x)[0]) {
    return kCFBooleanTrue;
  } else {
    return kCFBooleanFalse;
  }
}

CFNumberRef cf_int1(SEXP x) {
  CFNumberRef cn = CFNumberCreate(NULL, kCFNumberIntType, INTEGER(x));
  r_call_on_exit((finalizer_t) CFRelease, (void*) cn);
  return cn;
}

CFDataRef cf_raw(SEXP x) {
  CFDataRef cd = CFDataCreate(NULL, RAW(x), LENGTH(x));
  r_call_on_exit((finalizer_t) CFRelease, (void*) cd);
  return cd;
}

const void *cf_value(SEXPTYPE type, SEXP x) {
  switch(type) {
  case CHARSXP:
    return cf_chr1(x);
    break;
  case INTSXP:
    return cf_int1(x);
    break;
  case LGLSXP:
    return cf_lgl1(x);
    break;
  case RAWSXP:
    return cf_raw(x);
  default:
    error("Unsupported attribute type in oskeyring");
  }
}

// ------------------------------------------------------------------------
// Conversion from CF to SEXP
// ------------------------------------------------------------------------

SEXP as_chr1(CFStringRef cs) {
  if (cs == NULL) return(R_NilValue);
  const char *cstr = CFStringGetCStringPtr(cs, kCFStringEncodingUTF8);
  if (cstr != NULL) return Rf_ScalarString(Rf_mkCharCE(cstr, CE_UTF8));

  CFIndex length = CFStringGetLength(cs);
  CFIndex maxSize =
    CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
  char *buffer = (char *) malloc(maxSize);
  if (CFStringGetCString(cs, buffer, maxSize, kCFStringEncodingUTF8)) {
    SEXP ret = Rf_ScalarString(Rf_mkCharCE(buffer, CE_UTF8));
    free(buffer);
    return ret;
  } else {
    free(buffer);
    error("Failed to retrieve Keychain item attribute in UTF-8");
    return R_NilValue;
  }
}

SEXP as_lgl1(CFBooleanRef cb) {
  return ScalarLogical(cb == kCFBooleanTrue);
}

SEXP as_int1(CFNumberRef cn) {
  // Seems silly, but CF warns against integers stored as doubles...
  double ret;
  Boolean st = CFNumberGetValue(cn, kCFNumberDoubleType, &ret);
  if (!st) warning("Lossy conversion of number in Keychain attribute");
  return ScalarInteger((int) ret);
}

SEXP as_raw(CFDataRef cd) {
  size_t len = CFDataGetLength(cd);
  SEXP ret = PROTECT(allocVector(RAWSXP, len));
  CFDataGetBytes(cd, CFRangeMake(0, len), RAW(ret));
  UNPROTECT(1);
  return ret;
}

SEXP as_sexp(SEXPTYPE type, const void *x) {
  switch (type) {
  case CHARSXP:
    return as_chr1(x);
    break;
  case INTSXP:
    return as_int1(x);
    break;
  case LGLSXP:
    return as_lgl1(x);
    break;
  case RAWSXP:
    return as_raw(x);
    break;
  default:
    error("Internal oskeyring error, unsupported SEXPTYPE for attribute");
  }
}

// ------------------------------------------------------------------------
// Keychain item attributes
// ------------------------------------------------------------------------

#define S__GENERIC_PASSWORD "generic_password"
#define S__INTERNET_PASSWORD "internet_password"

struct macos_attr {
  CFStringRef cf_label;
  const char *r_name;
  CFTypeID cf_type;
  SEXPTYPE r_type;
};

static struct macos_attr macos_attr_list[16];

#define X(b,c,d,e) do {                                        \
    macos_attr_list[idx].cf_label = (void*) kSecAttr ## b;     \
    macos_attr_list[idx].r_name = c;                           \
    macos_attr_list[idx].cf_type = d;                          \
    macos_attr_list[idx++].r_type = e;                         \
  } while (0)

static void macos_init_attr_list() {
  /* already initialized? */
  if (macos_attr_list[0].cf_label != NULL) return;
  int idx = 0;
  X(Account,            "account",             CFStringGetTypeID(),  CHARSXP);
  X(AuthenticationType, "authentication_type", CFNumberGetTypeID(),  INTSXP);
  X(Comment,            "comment",             CFStringGetTypeID(),  CHARSXP);
  X(Description,        "description",         CFStringGetTypeID(),  CHARSXP);
  X(Generic,            "generic",             CFDataGetTypeID(),    RAWSXP);
  X(IsInvisible,        "is_invisible",        CFBooleanGetTypeID(), LGLSXP);
  X(IsNegative,         "is_negative",         CFBooleanGetTypeID(), LGLSXP);
  X(Label,              "label",               CFStringGetTypeID(),  CHARSXP);
  X(Path,               "path",                CFStringGetTypeID(),  CHARSXP);
  X(Port,               "port",                CFNumberGetTypeID(),  INTSXP);
  // Protocol
  X(Service,            "service",             CFStringGetTypeID(),  CHARSXP);
  X(SecurityDomain,     "security_domain",     CFStringGetTypeID(),  CHARSXP);
  X(Server,             "server",              CFStringGetTypeID(),  CHARSXP);
  X(Synchronizable,     "synchronizable",      CFBooleanGetTypeID(), LGLSXP);
  macos_attr_list[idx++].cf_label = NULL;
}

#undef X

struct macos_attr *oskeyring_find_attr(const char *name) {
  int i, num = sizeof(macos_attr_list) / sizeof(struct macos_attr);
  for (i = 0; i < num; i++) {
    if (!strcmp(name, macos_attr_list[i].r_name)) return &macos_attr_list[i];
  }
  error("Unknown Keychain item attribute: `%s`", name);
}

struct macos_attr *oskeyring_find_attr_by_cf_label(CFStringRef label) {
  int i, num = sizeof(macos_attr_list) / sizeof(struct macos_attr);
  for (i = 0; i < num; i++) {
    if (macos_attr_list[i].cf_label == label) return &macos_attr_list[i];
  }
  return NULL;
}

void oskeyring__add_class(CFMutableDictionaryRef query, SEXP class) {
  const char *cclass = CHAR(STRING_ELT(class, 0));
  if (!strcmp(S__GENERIC_PASSWORD, cclass)) {
    CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  } else if (!strcmp(S__INTERNET_PASSWORD, cclass)) {
    CFDictionaryAddValue(query, kSecClass, kSecClassInternetPassword);
  } else {
    error("Unknown Keychain item class: `%s`", cclass);
  }
}

void oskeyring__add_attributes(CFMutableDictionaryRef query, SEXP attr) {
  size_t i, n = LENGTH(attr);
  SEXP nms = getAttrib(attr, R_NamesSymbol);
  for (i = 0; i < n; i++) {
    const char *name = CHAR(STRING_ELT(nms, i));
    SEXP elt = VECTOR_ELT(attr, i);
    struct macos_attr *rec = oskeyring_find_attr(name);
    CFDictionaryAddValue(query, rec->cf_label, cf_value(rec->r_type, elt));
  }
}

// ------------------------------------------------------------------------
// Internal helpers
// ------------------------------------------------------------------------

const char *cf_string_to_char(CFStringRef cs) {
  CFIndex length = CFStringGetLength(cs);
  CFIndex maxSize =
    CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
  char *buffer = R_alloc(maxSize, 1);
  buffer[0] = '\0';
  CFStringGetCString(cs, buffer, maxSize, kCFStringEncodingUTF8);
  return buffer;
}

void oskeyring_macos_error(const char *func, OSStatus status) {
  CFStringRef str = SecCopyErrorMessageString(status, NULL);
  const char *buffer = cf_string_to_char(str);
  if (buffer) {
    error("oskeyring error (macOS Keychain), %s: %s", func, buffer);
  } else {
    error("oskeyring error (macOS Keychain), %s", func);
  }
}

void oskeyring_macos_handle_status(const char *func, OSStatus status) {
  if (status != errSecSuccess) oskeyring_macos_error(func, status);
}

SEXP oskeyring_as_item(SecKeychainItemRef item) {
  CFDictionaryRef dict = (CFDictionaryRef) item;
  CFStringRef cfclass = CFDictionaryGetValue(dict, kSecClass);
  char *class = 0;

  const char *inms[] = { "class", "value", "attributes", "" };
  SEXP ret = PROTECT(Rf_mkNamed(VECSXP, inms));
  setAttrib(
    ret,
    R_ClassSymbol,
    Rf_ScalarString(Rf_mkCharCE("oskeyring_macos_item", CE_UTF8))
  );

  if (cfclass == kSecClassGenericPassword) {
    class = S__GENERIC_PASSWORD;
  } else if (cfclass == kSecClassInternetPassword) {
    class = S__INTERNET_PASSWORD;
  } else {
    error("Unknown Keychain item class");
  }

  SET_VECTOR_ELT(ret, 0, Rf_ScalarString(Rf_mkCharCE(class, CE_UTF8)));
  SET_VECTOR_ELT(ret, 1, R_NilValue);

  CFIndex i, rn = 0, n = CFDictionaryGetCount(dict);

  CFTypeRef *keys = (CFTypeRef *) R_alloc(sizeof(CFTypeRef), n);
  CFDictionaryGetKeysAndValues(dict, (const void **) keys, NULL);

  for (i = 0; i < n; i++) {
    struct macos_attr *rec = oskeyring_find_attr_by_cf_label(keys[i]);
    rn += (rec != NULL);
  }

  SEXP attr = PROTECT(allocVector(VECSXP, rn));
  SEXP attrnms = PROTECT(allocVector(STRSXP, rn));
  setAttrib(attr, R_NamesSymbol, attrnms);
  SET_VECTOR_ELT(ret, 2, attr);
  UNPROTECT(2);

  for (i = 0, rn = 0; i < n; i++) {
    const CFStringRef key = keys[i];
    if (key == kSecClass) continue;
    struct macos_attr *rec = oskeyring_find_attr_by_cf_label(key);
    if (rec == NULL) continue;
    SET_STRING_ELT(attrnms, rn, Rf_mkCharCE(rec->r_name, CE_UTF8));
    SET_VECTOR_ELT(attr, rn, as_sexp(rec->r_type, CFDictionaryGetValue(dict, key)));
    rn++;
  }

  UNPROTECT(1);
  return ret;
}

SEXP oskeyring_as_item_list(CFArrayRef arr) {
  CFIndex i, num = CFArrayGetCount(arr);
  SEXP result = PROTECT(allocVector(VECSXP, num));
  for (i = 0; i < num; i++) {
    SecKeychainItemRef item =
      (SecKeychainItemRef) CFArrayGetValueAtIndex(arr, i);
    SET_VECTOR_ELT(result, i, oskeyring_as_item(item));
  }

  UNPROTECT(1);
  return result;
}

SecKeychainRef oskeyring_macos_open_keychain(const char *pathName) {
  SecKeychainRef keychain;
  OSStatus status = SecKeychainOpen(pathName, &keychain);
  oskeyring_macos_handle_status("cannot open keychain", status);

  /* We need to query the status, because SecKeychainOpen succeeds,
     even if the keychain file does not exists. (!) */
  SecKeychainStatus keychainStatus = 0;
  status = SecKeychainGetStatus(keychain, &keychainStatus);
  oskeyring_macos_handle_status("cannot open keychain", status);

  return keychain;
}

// ------------------------------------------------------------------------
// API
// ------------------------------------------------------------------------

SEXP oskeyring_macos_add(SEXP item, SEXP keychain) {

  // TODO: keychain

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    kCFAllocatorDefault, 0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);

  r_call_on_exit((finalizer_t) CFRelease, (void*) query);

  oskeyring__add_class(query, list_elt(item, "class"));
  CFDictionaryAddValue(query, kSecValueData, cf_raw(list_elt(item, "value")));
  oskeyring__add_attributes(query, list_elt(item, "attributes"));

  OSStatus status = SecItemAdd(query, NULL);
  oskeyring_macos_handle_status("cannot add keychain item", status);

  return R_NilValue;
}

SEXP oskeyring_macos_search(SEXP class, SEXP attributes,
                            SEXP match, SEXP keychain) {

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    kCFAllocatorDefault, 0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);

  r_call_on_exit((finalizer_t) CFRelease, (void*) query);

  oskeyring__add_class(query, class);
  oskeyring__add_attributes(query, attributes);
  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
  CFDictionarySetValue(query, kSecReturnData, kCFBooleanFalse);
  CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);

  // TODO: match
  // TODO: keychain

  CFArrayRef resArray = NULL;
  OSStatus status = SecItemCopyMatching(query, (CFTypeRef*) &resArray);

  /* If there are no matching elements, then SecItemCopyMatching
     returns with an error, so we need work around that and return an
     empty list instead. */

  if (status == errSecItemNotFound) {
    resArray = CFArrayCreate(NULL, NULL, 0, NULL);

  } else if (status != errSecSuccess) {
    if (resArray != NULL) CFRelease(resArray);
    oskeyring_macos_handle_status("cannot list passwords", status);
    return NULL;
  }

  r_call_on_exit((finalizer_t) CFRelease, (void*) resArray);

  return oskeyring_as_item_list(resArray);
}

SEXP oskeyring_macos_update(SEXP class, SEXP attributes,
                            SEXP match, SEXP update, SEXP keychain) {
  /* TODO */
  return R_NilValue;
}

SEXP oskeyring_macos_delete(SEXP class, SEXP attributes,
                            SEXP match, SEXP keychain) {
  /* TODO */
  return R_NilValue;
}

SEXP oskeyring_macos_keychain_create(SEXP keyring, SEXP password) {
  const char *ckeyring = CHAR(STRING_ELT(keyring, 0));
  const char *cpassword = CHAR(STRING_ELT(password, 0));

  SecKeychainRef result = NULL;

  OSStatus status = SecKeychainCreate(
    ckeyring,
    /* passwordLength = */ (UInt32) strlen(cpassword),
    (const void*) cpassword,
    /* promptUser = */ 0, /* initialAccess = */ NULL,
    &result);

  oskeyring_macos_handle_status("cannot create keychain", status);

  CFArrayRef keyrings = NULL;
  status = SecKeychainCopyDomainSearchList(
    kSecPreferencesDomainUser,
    &keyrings);

  if (status) {
    SecKeychainDelete(result);
    if (result != NULL) CFRelease(result);
    oskeyring_macos_handle_status("cannot create keychain", status);
  }

  /* We need to add the new keychain to the keychain search list,
     otherwise applications like Keychain Access will not see it.
     There is no API to append it, we need to query the current
     search list, add it, and then set the whole new search list.
     This is of course a race condition. :/ */

  CFIndex count = CFArrayGetCount(keyrings);
  CFMutableArrayRef newkeyrings =
    CFArrayCreateMutableCopy(NULL, count + 1, keyrings);
  CFArrayAppendValue(newkeyrings, result);
  status = SecKeychainSetDomainSearchList(
    kSecPreferencesDomainUser,
    newkeyrings);

  if (status) {
    SecKeychainDelete(result);
    if (result) CFRelease(result);
    if (keyrings) CFRelease(keyrings);
    if (newkeyrings) CFRelease(newkeyrings);
    oskeyring_macos_handle_status("cannot create keychain", status);
  }

  CFRelease(result);
  CFRelease(keyrings);
  CFRelease(newkeyrings);

  return R_NilValue;
}

SEXP oskeyring_macos_keychain_list() {
  // TODO
  return R_NilValue;
}

SEXP oskeyring_macos_keychain_delete(SEXP keyring) {

  const char *ckeyring = CHAR(STRING_ELT(keyring, 0));

  /* Need to remove it from the search list as well */

  CFArrayRef keyrings = NULL;
  OSStatus status = SecKeychainCopyDomainSearchList(
    kSecPreferencesDomainUser,
    &keyrings);
  oskeyring_macos_handle_status("cannot delete keyring", status);

  CFIndex i, count = CFArrayGetCount(keyrings);
  CFMutableArrayRef newkeyrings =
    CFArrayCreateMutableCopy(NULL, count, keyrings);
  for (i = 0; i < count; i++) {
    SecKeychainRef item =
      (SecKeychainRef) CFArrayGetValueAtIndex(keyrings, i);
    UInt32 pathLength = MAXPATHLEN;
    char pathName[MAXPATHLEN + 1];
    status = SecKeychainGetPath(item, &pathLength, pathName);
    pathName[pathLength] = '\0';
    if (status) {
      CFRelease(keyrings);
      CFRelease(newkeyrings);
      oskeyring_macos_handle_status("cannot delete keyring", status);
    }
    if (!strcmp(pathName, ckeyring)) {
      CFArrayRemoveValueAtIndex(newkeyrings, (CFIndex) i);
      status = SecKeychainSetDomainSearchList(
        kSecPreferencesDomainUser,
	newkeyrings);
      if (status) {
	CFRelease(keyrings);
	CFRelease(newkeyrings);
	oskeyring_macos_handle_status("cannot delete keyring", status);
      }
    }
  }

  /* If we haven't found it on the search list,
     then we just keep silent about it ... */

  CFRelease(keyrings);
  CFRelease(newkeyrings);

  /* And now remove the file as well... */
  SecKeychainRef keychain = oskeyring_macos_open_keychain(ckeyring);
  status = SecKeychainDelete(keychain);
  CFRelease(keychain);
  oskeyring_macos_handle_status("cannot delete keyring", status);

  return R_NilValue;
}

SEXP oskeyring_macos_keychain_lock(SEXP keyring) {
  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    oskeyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));
  OSStatus status = SecKeychainLock(keychain);
  if (keychain) CFRelease(keychain);
  oskeyring_macos_handle_status("cannot lock keychain", status);
  return R_NilValue;
}

SEXP oskeyring_macos_keychain_unlock(SEXP keyring, SEXP password) {
  const char *cpassword = CHAR(STRING_ELT(password, 0));
  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    oskeyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));
  OSStatus status = SecKeychainUnlock(
    keychain,
    (UInt32) strlen(cpassword),
     (const void*) cpassword,
    /* usePassword = */ TRUE);

  if (keychain) CFRelease(keychain);
  oskeyring_macos_handle_status("cannot unlock keychain", status);
  return R_NilValue;
}

SEXP oskeyring_macos_keychain_is_locked(SEXP keyring) {
  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    oskeyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));

  SecKeychainStatus kstatus;
  OSStatus status = SecKeychainGetStatus(keychain, &kstatus);
  if (status) oskeyring_macos_error("cannot get lock information", status);

  return ScalarLogical(! (kstatus & kSecUnlockStateStatus));
}

#define REGISTER(method, args) \
  { #method, (DL_FUNC) &method, args }

static const R_CallMethodDef callMethods[]  = {
  REGISTER(oskeyring_macos_add,    2),
  REGISTER(oskeyring_macos_search, 4),
  REGISTER(oskeyring_macos_update, 5),
  REGISTER(oskeyring_macos_delete, 4),

  REGISTER(oskeyring_macos_keychain_create,    2),
  REGISTER(oskeyring_macos_keychain_list,      0),
  REGISTER(oskeyring_macos_keychain_delete,    1),
  REGISTER(oskeyring_macos_keychain_lock,      1),
  REGISTER(oskeyring_macos_keychain_unlock,    2),
  REGISTER(oskeyring_macos_keychain_is_locked, 1),

  CLEANCALL_METHOD_RECORD,

  { NULL, NULL, 0 }
};

void R_init_oskeyring(DllInfo *dll) {
  R_registerRoutines(dll, NULL, callMethods, NULL, NULL);
  R_useDynamicSymbols(dll, FALSE);
  R_forceSymbols(dll, TRUE);
  cleancall_init();
  macos_init_attr_list();
}

#endif // __APPLE__
