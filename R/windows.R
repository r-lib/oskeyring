
#' Query and manipulate the Windows Credential Store
#'
#' @description
#' `windows_item_*` functions read, write, delete and list
#' credentials.
#'
#' @details
#' ## `windows_item_types()`
#'
#' `windows_item_types()` lists the currently supported credential
#' types.
#'
#' ```{r}
#' windows_item_types()
#' ```
#'
#' ## `windows_item()`
#'
#' `windows_item()` creates a Windows credential, that can be
#' then added to the credential store.
#'
#' ```{r}
#' it <- windows_item("secret", "my-host-password")
#' it
#' ```
#'
#' ## `windows_item_write()`
#'
#' Writes an item to the credential store.
#'
#' ```{r, include = FALSE, eval = get_os() == "win"}
#' # Remove to make sure it is not there
#' tryCatch(
#'   windows_item_delete("my-host-password"),
#'   error = function(err) NULL
#' )
#' ```
#'
#' ```{r, eval = get_os() == "win"}
#' windows_item_write(it)
#' ```
#'
#' ## `windows_item_read()`
#'
#' Reads a credential with the specified type and `target_name`.
#'
#' ```{r, eval = get_os() == "win"}
#' windows_item_read("my-host-password")
#' ```
#'
#' ## `windows_item_enumerate()`
#'
#' List all credentials that match a prefix.
#'
#' ```{r, eval = get_os() == "win"}
#' windows_item_enumerate(filter = "my-*")
#' ```
#'
#' ## `windows_item_delete()`
#'
#' Delete a credential:
#'
#' ```{r, eval = get_os() == "win"}
#' windows_item_delete("my-host-password")
#' windows_item_enumerate(filter = "my-*")
#' ```
#'
#' @seealso The API documentation at
#' <https://docs.microsoft.com/en-us/windows/win32/api/wincred/>
#' @export
#' @return `windows_item_types()` returns a character vector, the
#' currently supported credential types.
#' @rdname windows_credentials
#' @name windows_credentials
#' @examples
#' # See above

windows_item_types <- function() {
  c("generic", "domain_password", "domain_certificate",
    "domain_visible_password")
}

#' @param credential_blob The secret credential, a password,
#' certificate or key. See also
#' <https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw>
#' This can be a raw vector, or a string. If it is a string, then it
#' will be converted to Unicode, without the terminating zero.
#' It can also be `NULL`, to be used with the `preserve = TRUE`
#' argument of `windows_item_write()`.
#' @param target_name The name of the credential. The `target_name`
#' and `type` members uniquely identify the credential. This member
#' cannot be changed after the credential is created. Instead, the
#' credential with the old name should be deleted and the credential
#' with the new name created. This member cannot be longer than
#' `CRED_MAX_GENERIC_TARGET_NAME_LENGTH` (32767) characters.
#' This member is case-insensitive.
#' @param type The type of the credential. This member cannot be
#' changed after the credential is created. See `windows_item_types()`
#' for possible values.
#' @param comment If not `NULL`, then a string comment from the user
#' that describes this credential. This member cannot be longer than
#' `CRED_MAX_STRING_LENGTH` (256) characters. It is stored as a Unicode
#' string.
#' @param persist Defines the persistence of this credential.
#' * `"local_machine"`: The credential persists for all subsequent
#'   logon sessions on this same computer. It is visible to other
#'   logon sessions of this same user on this same computer and not
#'   visible to logon sessions for this user on other computers.
#' * `"session"`: The credential persists for the life of the logon
#'   session. It will not be visible to other logon sessions of this
#'   same user. It will not exist after this user logs off and back on.
#' * `"enterprise"`: The credential persists for all subsequent logon
#'   sessions on this same computer. It is visible to other logon
#'   sessions of this same user on this same computer and to logon
#'   sessions for this user on other computers.
#' @param attributes Application-defined attributes that are
#'   associated with the credential. This is `NULL` or a named list
#'   of raw or string vectors. String vectors are converted to
#'   Unicode, without the terminating zero. A credential can have at
#'   most 64 attributes, the names of the attributes cannot be
#'   longer than `CRED_MAX_STRING_LENGTH` (256) characters each, and
#'   the attributes themselves cannot be longer than
#'   `CRED_MAX_VALUE_SIZE` (256) bytes.
#' @param target_alias Alias for the `target_name` member.
#' This member can be read and written. It cannot be longer than
#' `CRED_MAX_STRING_LENGTH` (256) characters. It is stored in Unicode.
#' @param username `NULL` or the user name of the account used to
#' connect to `target_name`.
#' @return `windows_item()` returns an `oskeyring_windows_item`
#' object.
#' @export
#' @rdname windows_credentials

windows_item <- function(credential_blob, target_name,
                         type = "generic", comment = NULL,
                         persist = c("local_machine", "session",
                           "enterprise"), attributes = list(),
                         target_alias = NULL, username = NULL) {

  persist <- match.arg(persist)
  stopifnot(
    is.null(credential_blob) || is_string_or_raw(credential_blob),
    is_string(target_name),
    is_string(type) && type %in% windows_item_types(),
    is.null(comment) || is_string(comment),
    is_named_list(attributes) &&
      all(vapply(attributes, function(x) is_string_or_raw(x), logical(1))),
    is.null(target_alias) || is_string(target_alias),
    is.null(username) || is_string(username)
  )

  structure(
    list(
      type = type,
      target_name = target_name,
      credential_blob = credential_blob,
      comment = comment,
      persist = persist,
      attributes = attributes,
      target_alias = target_alias,
      username = username
    ),
    class = "oskeyring_windows_item"
  )
}

#' @export

format.oskeyring_windows_item <- function(x, ...) {
  c(
    paste0("<oskeyring_windows_item: ", x$type, ">"),
    paste0(" target_name: ", x$target_name),
    if (!is.null(x$comment)) paste0(" comment: ", x$comment),
    paste0(" persist: ", x$persist),
    if (!is.null(x$target_alias)) paste0(" target_alias: ", x$target_alias),
    if (!is.null(x$username)) paste0(" username: ", x$username),
    if (length(x$attributes) > 0) {
      c(" attributes:",
        paste0("  ", names(x$attributes), ": ", format_attr(x$attributes))
      )
    },
    if (!is.null(x$credential_blob)) " credential_blob: <-- hidden -->"
  )
}

#' @export

print.oskeyring_windows_item <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}

#' @return `windows_item_read()` returns an `oskeyring_windows_item`
#' object.
#' @export
#' @rdname windows_credentials

windows_item_read <- function(target_name, type = "generic") {
  os_check("Windows")
  stopifnot(
    is_string(target_name),
    is_string(type) && type %in% windows_item_types()
  )

  target_name <- to_ucs2(target_name)
  item <- call_with_cleanup(oskeyring_windows_read, target_name, type)

  windows_item_from_ucs2(item)
}

#' @param item `oskeyring_windows_item` object to write.
#' @param preserve The credential BLOB from an existing credential
#' is preserved with the same credential name and credential type.
#' The `credential_blob` of the passed `oskeyring_windows_item`
#' object must be `NULL`.
#' @return `windows_item_write()` returns `NULL`, invisibly.
#' @export
#' @rdname windows_credentials

windows_item_write <- function(item, preserve = FALSE) {
  os_check("Windows")
  stopifnot(
    inherits(item, "oskeyring_windows_item"),
    is_flag(preserve)
  )

  encode <- function(x) {
    if (is.character(x)) {
      iconv(x, to = "UCS-2LE", toRaw = TRUE)[[1]]
    } else if (is.null(x) || is.raw(x)) {
      x
    } else {
      stop("Unsupported data type in Windows keychain item")
    }
  }
  item$credential_blob <- encode(item$credential_blob)
  item$target_name <- to_ucs2(item$target_name)
  item["comment"] <- list(to_ucs2(item$comment))
  item["attribute_names"] <- list(lapply(names(item$attributes), to_ucs2))
  item["attributes"] <- list(lapply(item$attributes, encode))
  item["target_alias"] <- list(to_ucs2(item$target_alias))
  item["username"] <- list(to_ucs2(item$username))

  invisible(call_with_cleanup(oskeyring_windows_write, item, preserve))
}

#' @return `windows_item_delete()` returns `NULL`, invisibly.
#' @export
#' @rdname windows_credentials

windows_item_delete <- function(target_name, type = "generic") {
  os_check("Windows")
  stopifnot(
    is_string(target_name),
    is_string(type) && type %in% windows_item_types()
  )

  target_name <- to_ucs2(target_name)
  invisible(call_with_cleanup(oskeyring_windows_delete, target_name, type))
}

#' @param filter If not `NULL`, then a string to filter the
#' credentials. Only credentials with a `target_name` matching the
#' filter will be returned. The filter specifies a name prefix
#' followed by an asterisk. For instance, the filter `"FRED*"` will
#' return all credentials with a `target_name` beginning with the
#' string `"FRED"`.
#' @param all Whether to use the `CRED_ENUMERATE_ALL_CREDENTIALS`
#' flag to enumerate all credentials. If this is `TRUE`, then `filter`
#' must be `NULL`. If this is `TRUE`, then the target name of each
#' credential is returned in the `"namespace:attribute=target`" format.
#' @return `windows_item_enumerate()` returns a list of
#' `oskeyring_windows_item` items.
#' @export
#' @rdname windows_credentials

windows_item_enumerate <- function(filter = NULL, all = FALSE) {
  os_check("Windows")
  stopifnot(
    is.null(filter) || is_string(filter),
    is_flag(all)
  )

  if (!is.null(filter)) filter <- to_ucs2(filter)
  items <- call_with_cleanup(oskeyring_windows_enumerate, filter, all)
  lapply(items, windows_item_from_ucs2)
}

windows_item_from_ucs2 <- function(item) {
  item$target_name <- from_ucs2(list(item$target_name))
  item["comment"] <- list(from_ucs2(list(item$comment)))
  item["target_alias"] <- list(from_ucs2(list(item$target_alias)))
  item["username"] <- list(from_ucs2(list(item$username)))

  if (length(item$attributes)) {
    attr <- item$attributes
    names(attr) <- from_ucs2(item$attribute_names)
    item["attributes"] <- list(attr)
  } else {
    item["attributes"] <- list(NULL)
  }
  item$attribute_names <- NULL

  item
}

to_ucs2 <- function(x) {
  if (is.null(x)) return(NULL)
  stopifnot(is_string(x))
  c(
    iconv(enc2utf8(x), from = "UTF-8", to = "UCS-2LE", toRaw = TRUE)[[1]],
    raw(2)
  )
}

from_ucs2 <- function(x) {
  if (length(x) == 1 && is.null(x[[1]])) return(NULL)
  iconv(x, from = "UCS-2LE", to = "UTF-8")
}
