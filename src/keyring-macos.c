
/* Avoid warning about empty compilation unit. */
void keyring_macos_dummy() { }

#ifdef __APPLE__

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <R.h>
#include <R_ext/Rdynload.h>
#include <Rinternals.h>

#include <sys/param.h>
#include <string.h>

#include "oskeyring.h"

// ------------------------------------------------------------------------
// Internal helpers
// ------------------------------------------------------------------------

void keyring_macos_error(const char *func, OSStatus status) {
  CFStringRef str = SecCopyErrorMessageString(status, NULL);
  CFIndex length = CFStringGetLength(str);
  CFIndex maxSize =
    CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
  char *buffer = R_alloc(maxSize, 1);

  if (CFStringGetCString(str, buffer, maxSize, kCFStringEncodingUTF8)) {
    error("keyring error (macOS Keychain), %s: %s", func, buffer);

  } else {
    error("keyring error (macOS Keychain), %s", func);
  }
}

void keyring_macos_handle_status(const char *func, OSStatus status) {
  if (status != errSecSuccess) keyring_macos_error(func, status);
}

SecKeychainRef keyring_macos_open_keychain(const char *pathName) {
  SecKeychainRef keychain;
  OSStatus status = SecKeychainOpen(pathName, &keychain);
  keyring_macos_handle_status("cannot open keychain", status);

  /* We need to query the status, because SecKeychainOpen succeeds,
     even if the keychain file does not exists. (!) */
  SecKeychainStatus keychainStatus = 0;
  status = SecKeychainGetStatus(keychain, &keychainStatus);
  keyring_macos_handle_status("cannot open keychain", status);

  return keychain;
}

CFStringRef cf_chr1(SEXP x) {
  const char *cx = CHAR(STRING_ELT(x, 0));
  return CFStringCreateWithCString(NULL, cx, kCFStringEncodingUTF8);
}

CFBooleanRef cf_lgl1(SEXP x) {
  if (LOGICAL(x)[0]) {
    return kCFBooleanTrue;
  } else {
    return kCFBooleanFalse;
  }
}

CFNumberRef cf_int1(SEXP x) {
  return CFNumberCreate(NULL, kCFNumberIntType, INTEGER(x));
}

CFDataRef cf_raw(SEXP x) {
  return CFDataCreate(NULL, RAW(x), LENGTH(x));
}

void oskeyring__add_class(CFMutableDictionaryRef query, SEXP class) {
  const char *cclass = CHAR(STRING_ELT(class, 0));
  if (!strcmp("generic_password", cclass)) {
    CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  } else if (!strcmp("internet_password", cclass)) {
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
    if (!strcmp("account", name)) {
      CFDictionaryAddValue(query, kSecAttrAccount, cf_chr1(elt));
    } else if (!strcmp("authentication_type", name)) {
      // TODO
    } else if (!strcmp("comment", name)) {
      CFDictionaryAddValue(query, kSecAttrComment, cf_chr1(elt));
    } else if (!strcmp("description", name)) {
      CFDictionaryAddValue(query, kSecAttrDescription, cf_chr1(elt));
    } else if (!strcmp("generic", name)) {
      // This can be anything in macOS, but character(1) for us
      CFDictionaryAddValue(query, kSecAttrGeneric, cf_chr1(elt));
    } else if (!strcmp("is_invisible", name)) {
      CFDictionaryAddValue(query, kSecAttrIsInvisible, cf_lgl1(elt));
    } else if (!strcmp("is_negative", name)) {
      CFDictionaryAddValue(query, kSecAttrIsNegative, cf_lgl1(elt));
    } else if (!strcmp("label", name)) {
      CFDictionaryAddValue(query, kSecAttrLabel, cf_chr1(elt));
    } else if (!strcmp("path", name)) {
      CFDictionaryAddValue(query, kSecAttrPath, cf_chr1(elt));
    } else if (!strcmp("port", name)) {
      CFDictionaryAddValue(query, kSecAttrPort, cf_int1(elt));
    } else if (!strcmp("protocol", name)) {
      // TODO
    } else if (!strcmp("service", name)) {
      CFDictionaryAddValue(query, kSecAttrService, cf_chr1(elt));      
    } else if (!strcmp("security_domain", name)) {
      CFDictionaryAddValue(query, kSecAttrSecurityDomain, cf_chr1(elt));
    } else if (!strcmp("server", name)) {
      CFDictionaryAddValue(query, kSecAttrServer, cf_chr1(elt));      
    } else if (!strcmp("synchronizable", name)) {
      CFDictionaryAddValue(query, kSecAttrSynchronizable, cf_lgl1(elt));
    } else {
      error("Unknown Keychain item attribute: `%s`", name);
    }
  }
}

// ------------------------------------------------------------------------
// API
// ------------------------------------------------------------------------

SEXP oskeyring_macos_add(SEXP item, SEXP keychain) {

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    kCFAllocatorDefault, 0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);

  oskeyring__add_class(query, list_elt(item, "class"));
  CFDictionaryAddValue(query, kSecValueData, cf_raw(list_elt(item, "value")));
  oskeyring__add_attributes(query, list_elt(item, "attributes"));

  OSStatus status = SecItemAdd(query, NULL);
  keyring_macos_handle_status("cannot add keychain item", status);
  
  return R_NilValue;
}

SEXP oskeyring_macos_search(SEXP class, SEXP attributes,
                            SEXP match, SEXP keychain) {
  /* TODO */
  return R_NilValue;
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

SEXP keyring_macos_get(SEXP keyring, SEXP service, SEXP username) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty :CHAR(STRING_ELT(username, 0));

  void *data;
  UInt32 length;
  SEXP result;

  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));

  OSStatus status = SecKeychainFindGenericPassword(
    keychain,
    (UInt32) strlen(cservice), cservice,
    (UInt32) strlen(cusername), cusername,
    &length, &data,
    /* itemRef = */ NULL);

  if (keychain != NULL) CFRelease(keychain);

  keyring_macos_handle_status("cannot get password", status);

  result = PROTECT(allocVector(RAWSXP, length));
  memcpy(RAW(result), data, length);
  SecKeychainItemFreeContent(NULL, data);

  UNPROTECT(1);
  return result;
}

SEXP keyring_macos_set(SEXP keyring, SEXP service, SEXP username,
		       SEXP password) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));
  SecKeychainItemRef item;

  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));

  /* Try to find it, and it is exists, update it */

  OSStatus status = SecKeychainFindGenericPassword(
    keychain,
    (UInt32) strlen(cservice), cservice,
    (UInt32) strlen(cusername), cusername,
    /* passwordLength = */ NULL, /* passwordData = */ NULL,
    &item);

  if (status == errSecItemNotFound) {
    status = SecKeychainAddGenericPassword(
      keychain,
      (UInt32) strlen(cservice), cservice,
      (UInt32) strlen(cusername), cusername,
      (UInt32) LENGTH(password), RAW(password),
      /* itemRef = */ NULL);

  } else {
    status = SecKeychainItemModifyAttributesAndData(
      item,
      /* attrList= */ NULL,
      (UInt32) LENGTH(password), RAW(password));
    CFRelease(item);
  }

  if (keychain != NULL) CFRelease(keychain);

  keyring_macos_handle_status("cannot set password", status);

  return R_NilValue;
}

SEXP keyring_macos_delete(SEXP keyring, SEXP service, SEXP username) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));

  SecKeychainRef keychain =
    isNull(keyring) ? NULL : keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));
  SecKeychainItemRef item;

  OSStatus status = SecKeychainFindGenericPassword(
    keychain,
    (UInt32) strlen(cservice), cservice,
    (UInt32) strlen(cusername), cusername,
    /* *passwordLength = */ NULL, /* *passwordData = */ NULL,
    &item);

  if (status != errSecSuccess) {
    if (keychain != NULL) CFRelease(keychain);
    keyring_macos_error("cannot delete password", status);
  }

  status = SecKeychainItemDelete(item);
  if (status != errSecSuccess) {
    if (keychain != NULL) CFRelease(keychain);
    keyring_macos_error("cannot delete password", status);
  }

  if (keychain != NULL) CFRelease(keychain);
  CFRelease(item);

  return R_NilValue;
}

static void keyring_macos_list_item(SecKeychainItemRef item, SEXP result,
				    int idx) {
  SecItemClass class;
  SecKeychainAttribute attrs[] = {
    { kSecServiceItemAttr },
    { kSecAccountItemAttr }
  };
  SecKeychainAttributeList attrList = { 2, attrs };

  /* This should not happen, not a keychain... */
  if (SecKeychainItemGetTypeID() != CFGetTypeID(item)) {
    SET_STRING_ELT(VECTOR_ELT(result, 0), idx, mkChar(""));
    SET_STRING_ELT(VECTOR_ELT(result, 1), idx, mkChar(""));
    return;
  }

  OSStatus status = SecKeychainItemCopyContent(item, &class, &attrList,
					       /* length = */ NULL,
					       /* outData = */ NULL);
  keyring_macos_handle_status("cannot list passwords", status);
  SET_STRING_ELT(VECTOR_ELT(result, 0), idx,
		 mkCharLen(attrs[0].data, attrs[0].length));
  SET_STRING_ELT(VECTOR_ELT(result, 1), idx,
		 mkCharLen(attrs[1].data, attrs[1].length));
  SecKeychainItemFreeContent(&attrList, NULL);
}

CFArrayRef keyring_macos_list_get(const char *ckeyring,
				  const char *cservice) {

  CFStringRef cfservice = NULL;

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    kCFAllocatorDefault, 0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);

  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
  CFDictionarySetValue(query, kSecReturnData, kCFBooleanFalse);
  CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);

  CFArrayRef searchList = NULL;
  if (ckeyring) {
    SecKeychainRef keychain = keyring_macos_open_keychain(ckeyring);
    searchList = CFArrayCreate(NULL, (const void **) &keychain, 1,
			       &kCFTypeArrayCallBacks);
    CFDictionaryAddValue(query, kSecMatchSearchList, searchList);
  }

  if (cservice) {
    cfservice = CFStringCreateWithBytes(
      /* alloc = */ NULL,
      (const UInt8*) cservice, strlen(cservice),
      kCFStringEncodingUTF8,
      /* isExternalRepresentation = */ 0);
    CFDictionaryAddValue(query, kSecAttrService, cfservice);
  }

  CFArrayRef resArray = NULL;
  OSStatus status = SecItemCopyMatching(query, (CFTypeRef*) &resArray);
  CFRelease(query);
  if (cfservice != NULL) CFRelease(cfservice);
  if (searchList != NULL) CFRelease(searchList);

  /* If there are no elements in the keychain, then SecItemCopyMatching
     returns with an error, so we need work around that and return an
     empty list instead. */

  if (status == errSecItemNotFound) {
    resArray = CFArrayCreate(NULL, NULL, 0, NULL);
    return resArray;

  } else if (status != errSecSuccess) {
    if (resArray != NULL) CFRelease(resArray);
    keyring_macos_handle_status("cannot list passwords", status);
    return NULL;

  } else {
    return resArray;
  }
}

SEXP keyring_macos_list(SEXP keyring, SEXP service) {

  const char *ckeyring =
    isNull(keyring) ? NULL : CHAR(STRING_ELT(keyring, 0));
  const char *cservice =
    isNull(service) ? NULL : CHAR(STRING_ELT(service, 0));

  CFArrayRef resArray = keyring_macos_list_get(ckeyring, cservice);
  CFIndex i, num = CFArrayGetCount(resArray);
  SEXP result;
  PROTECT(result = allocVector(VECSXP, 2));
  SET_VECTOR_ELT(result, 0, allocVector(STRSXP, num));
  SET_VECTOR_ELT(result, 1, allocVector(STRSXP, num));
  for (i = 0; i < num; i++) {
    SecKeychainItemRef item =
      (SecKeychainItemRef) CFArrayGetValueAtIndex(resArray, i);
    keyring_macos_list_item(item, result, (int) i);
  }

  CFRelease(resArray);
  UNPROTECT(1);
  return result;
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

  keyring_macos_handle_status("cannot create keychain", status);

  CFArrayRef keyrings = NULL;
  status = SecKeychainCopyDomainSearchList(
    kSecPreferencesDomainUser,
    &keyrings);

  if (status) {
    SecKeychainDelete(result);
    if (result != NULL) CFRelease(result);
    keyring_macos_handle_status("cannot create keychain", status);
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
    keyring_macos_handle_status("cannot create keychain", status);
  }

  CFRelease(result);
  CFRelease(keyrings);
  CFRelease(newkeyrings);

  return R_NilValue;
}

SEXP oskeyring_macos_keychain_list() {
  CFArrayRef keyrings = NULL;
  OSStatus status =
    SecKeychainCopyDomainSearchList(kSecPreferencesDomainUser, &keyrings);
  keyring_macos_handle_status("cannot list keyrings", status);

  /* TODO: list system and other keyrings as well */

  CFIndex i, num = CFArrayGetCount(keyrings);

  SEXP result = PROTECT(allocVector(VECSXP, 3));
  SET_VECTOR_ELT(result, 0, allocVector(STRSXP, num));
  SET_VECTOR_ELT(result, 1, allocVector(INTSXP, num));
  SET_VECTOR_ELT(result, 2, allocVector(LGLSXP, num));

  for (i = 0; i < num; i++) {
    SecKeychainRef keychain =
      (SecKeychainRef) CFArrayGetValueAtIndex(keyrings, i);
    UInt32 pathLength = MAXPATHLEN;
    char pathName[MAXPATHLEN + 1];
    status = SecKeychainGetPath(keychain, &pathLength, pathName);
    pathName[pathLength] = '\0';
    if (status) {
      CFRelease(keyrings);
      keyring_macos_handle_status("cannot list keyrings", status);
    }
    SET_STRING_ELT(VECTOR_ELT(result, 0), i, mkCharLen(pathName, pathLength));

    CFArrayRef resArray =
      keyring_macos_list_get(pathName, /* cservice = */ NULL);
    CFIndex numitems = CFArrayGetCount(resArray);
    CFRelease(resArray);
    INTEGER(VECTOR_ELT(result, 1))[i] = (int) numitems;

    SecKeychainStatus kstatus;
    status = SecKeychainGetStatus(keychain, &kstatus);
    if (status) {
      LOGICAL(VECTOR_ELT(result, 2))[i] = NA_LOGICAL;
    } else {
      LOGICAL(VECTOR_ELT(result, 2))[i] =
	! (kstatus & kSecUnlockStateStatus);
    }
  }

  CFRelease(keyrings);

  UNPROTECT(1);
  return result;
}

SEXP oskeyring_macos_keychain_delete(SEXP keyring) {

  const char *ckeyring = CHAR(STRING_ELT(keyring, 0));

  /* Need to remove it from the search list as well */

  CFArrayRef keyrings = NULL;
  OSStatus status = SecKeychainCopyDomainSearchList(
    kSecPreferencesDomainUser,
    &keyrings);
  keyring_macos_handle_status("cannot delete keyring", status);

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
      keyring_macos_handle_status("cannot delete keyring", status);
    }
    if (!strcmp(pathName, ckeyring)) {
      CFArrayRemoveValueAtIndex(newkeyrings, (CFIndex) i);
      status = SecKeychainSetDomainSearchList(
        kSecPreferencesDomainUser,
	newkeyrings);
      if (status) {
	CFRelease(keyrings);
	CFRelease(newkeyrings);
	keyring_macos_handle_status("cannot delete keyring", status);
      }
    }
  }

  /* If we haven't found it on the search list,
     then we just keep silent about it ... */

  CFRelease(keyrings);
  CFRelease(newkeyrings);

  /* And now remove the file as well... */
  SecKeychainRef keychain = keyring_macos_open_keychain(ckeyring);
  status = SecKeychainDelete(keychain);
  CFRelease(keychain);
  keyring_macos_handle_status("cannot delete keyring", status);

  return R_NilValue;
}

SEXP oskeyring_macos_keychain_lock(SEXP keyring) {
  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));
  OSStatus status = SecKeychainLock(keychain);
  if (keychain) CFRelease(keychain);
  keyring_macos_handle_status("cannot lock keychain", status);
  return R_NilValue;
}

SEXP oskeyring_macos_keychain_unlock(SEXP keyring, SEXP password) {
  const char *cpassword = CHAR(STRING_ELT(password, 0));
  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));
  OSStatus status = SecKeychainUnlock(
    keychain,
    (UInt32) strlen(cpassword),
     (const void*) cpassword,
    /* usePassword = */ TRUE);

  if (keychain) CFRelease(keychain);
  keyring_macos_handle_status("cannot unlock keychain", status);
  return R_NilValue;
}

SEXP oskeyring_macos_keychain_is_locked(SEXP keyring) {
  SecKeychainRef keychain =
    isNull(keyring) ? NULL :
    keyring_macos_open_keychain(CHAR(STRING_ELT(keyring, 0)));

  SecKeychainStatus kstatus;
  OSStatus status = SecKeychainGetStatus(keychain, &kstatus);
  if (status) keyring_macos_error("cannot get lock information", status);

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

  { NULL, NULL, 0 }
};

void R_init_keyring(DllInfo *dll) {
  R_registerRoutines(dll, NULL, callMethods, NULL, NULL);
  R_useDynamicSymbols(dll, FALSE);
  R_forceSymbols(dll, TRUE);
}

#endif // __APPLE__
