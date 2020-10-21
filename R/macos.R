
#' Query and manipulate the macOS Keychain
#'
#' @description
#' `macos_item_*` functions add, delete, update and search Keychain items.
#'
#' `macos_keychain_*` functions create, delete, list, lock, unlock
#' keychains.
#'
#' `macos_item_classes()` lists the supported Keychain item classes.
#' `macos_item_attr()` lists the supported attributes for these classes.
#' `macos_item_match_options()` lists the options supported by the
#' `match` argument of `macos_item_search()`.
#'
#' @details
#' # Keychain items
#'
#' `macos_item_classes()` returns the currently supported Keychain item
#' classes.
#'
#' ```{r}
#' macos_item_classes()
#' ```
#'
#' `macos_item()` creates a new Keychain item. See the next section about
#' the attributes that are supported for the various item types.
#'
#' ```{r}
#' it <- macos_item("secret", list(service = "My service", account = "Gabor"))
#' it
#' ```
#'
#' `macos_item_add()` adds an item to the keychain. If there is already an
#' item with the same primary keys, then it will error.
#'
#' ```{r, include = FALSE, eval = get_os() == "macos"}
#' # Remove, to make sure that 'add' works
#' tryCatch(
#'   macos_item_delete(attributes = list(service = "My service")),
#'   error = function(e) NULL
#' )
#' ```
#'
#' ```{r, eval = get_os() == "macos"}
#' macos_item_add(it)
#' ```
#'
#' `macos_item_search()` searches for Keychain items. If `return_data` is
#' `TRUE` then it also returns the secret data. Returning the secret data
#' might create a password entry dialog. If `return_data` is `TRUE` then
#' you need to set the `limit` match condition to a (small) finite number.
#'
#' ```{r, eval = get_os() == "macos"}
#' macos_item_search(attributes = list(service = "My service"))
#' ```
#'
#' `macos_item_update()` updates existing Keychain items.
#'
#' ```{r, eval = get_os() == "macos"}
#' macos_item_update(
#'   attributes = list(service = "My service", account = "Gabor"),
#'   update = list(account = "Gabor Csardi")
#' )
#' macos_item_search(attributes = list(service = "My service"))
#' ```
#'
#' `macos_item_delete()` deletes one or more Keychain items. Note that
#' all matching items will be deleted.
#'
#' ```{r, eval = get_os() == "macos"}
#' macos_item_delete(attributes = list(service = "My service"))
#' macos_item_search(attributes = list(service = "My service"))
#' ```
#'
#' ## Keychain Item Attributes
#'
#' * The set of supported attributes depends on the class of the item.
#' * oskeyring supports the following item classes currently:
#'   `r paste(macos_item_classes(), collapse = ", ")`.
#' * A subset of the attributes form a _primary key_. It is not possible
#'   to add more than one item with the same primary key. See the
#'   primary keys for the various classes below.
#' * oskeyring does not currently support all attributes that the
#'   Keychain Services AIP supports.
#' * Some attributes are read-only. If you try to set them when adding
#'   or updating items, they will be ignored.
#' * If an attribute is not included in the return value of
#'   `macos_item_search()` then it is not set, and its default value is in
#'   effect.
#'
#' ### Attributes for generic passwords
#'
#' `r item_list(macos_item_attr()[["generic_password"]])`
#'
#' ### Attributes for internet passwords
#'
#' `r item_list(macos_item_attr()[["internet_password"]])`
#'
#' # Search Parameters
#'
#' osxkeychain only supports a limited set of search parameters.
#' You can provide these for `macos_item_search()` as the `match` argument:
#'
#' `r item_list(macos_item_match_options())`
#'
#' # Keychains
#'
#' macOs supports multiple keychains.
#' There is always a default keychain, which is the user's login keychain,
#' unless configured differently.
#' There is also a keychain search list.
#' Keychains may belong into four non-exclusive categories, see the
#' `domain` argument of `macos_keychain_list()`.
#' A keychain is stored in an encrypted file on the disk, see the first
#' column of the output of `macos_keychain_list()`.
#'
#' `macos_item_*()` functions have a `keychain` argument to direct or
#' restrict the operation to a single keychain only. These are the defaults:
#' * `macos_item_add()` adds the item to the default keychain.
#' * `macos_item_search()` searches all keychains in the search list.
#' * `macos_item_update()` updates matching items on all keychains in the
#'   search list.
#' * `macos_item_delete()` deletes matching items from all keychains in the
#'   search list.
#'
#' `macos_keychain_create()` creates a new keychain.
#'
#' `macos_keychain_list()` lists all keychains on the search list.
#'
#' ```r
#' new <- "~/Library/Keychains/test.keychain-db"
#' macos_keychain_create(new, password = "secret")
#' macos_keychain_list()
#' ```
#'
#' ```r
#' ##                                                     path is_unlocked
#' ## 1 /Users/gaborcsardi/Library/Keychains/login.keychain-db        TRUE
#' ## 2 /Users/gaborcsardi/Library/Keychains/shiny.keychain-db       FALSE
#' ## 3  /Users/gaborcsardi/Library/Keychains/test.keychain-db        TRUE
#' ## 4                     /Library/Keychains/System.keychain       FALSE
#' ##   is_readable is_writeable
#' ## 1        TRUE         TRUE
#' ## 2        TRUE        FALSE
#' ## 3        TRUE         TRUE
#' ## 4        TRUE        FALSE
#' ```
#'
#' `macos_keychain_lock()` locks a keychain.
#' `macos_keychain_unlock()` unlocks a keychain.
#' `macos_keychain_is_locked()` checks if a keychain is locked.
#'
#' ```r
#' macos_keychain_lock(new)
#' macos_keychain_is_locked(new)
#' ```
#'
#' ```r
#' ## [1] TRUE
#' ```
#'
#' ```r
#' macos_keychain_unlock(new, password = "secret")
#' macos_keychain_is_locked(new)
#' ```
#'
#' ```r
#' ## [1] FALSE
#' ```
#'
#' `macos_keychain_delete()` deletes a keychain: it removes it from the
#' search list and deletes the data from the disk. It currently refuses to
#' delete the user's login keychain and the system keychain. Use Keychain
#' Access instead if you want to delete these. (Only do this if you are
#' aware of the bad consequences.)
#'
#' ```r
#' macos_keychain_delete(new)
#' macos_keychain_list()
#' ```
#'
#' ```r
#' ##                                                     path is_unlocked
#' ## 1 /Users/gaborcsardi/Library/Keychains/login.keychain-db        TRUE
#' ## 2 /Users/gaborcsardi/Library/Keychains/shiny.keychain-db       FALSE
#' ## 3                     /Library/Keychains/System.keychain       FALSE
#' ##   is_readable is_writeable
#' ## 1        TRUE         TRUE
#' ## 2        TRUE        FALSE
#' ## 3        TRUE        FALSE
#' ```
#'
#' @seealso The Keychain Services API documentation at
#' <https://developer.apple.com/documentation/security/keychain_services>.
#' @export
#' @rdname macos_keychain
#' @name macos_keychain
#' @examples
#' # See above

macos_item_classes <- function() {
  # TODO: support the rest
  # c("generic_password", "internet_password", "certificate", "key", "identity")
  c("generic_password", "internet_password")
}

# ------------------------------------------------------------------------
# Keychain items
# ------------------------------------------------------------------------

#' @param class Item class, see [macos_item_classes()] for possible values.
#' @param value Value of the item, a password, key or certificate. It must
#' a raw vector or a string. If it is a string, then it is converted to
#' UTF-8.
#' @param attributes Item class dependent attributes in a named list.
#' See possible entries below
#'
#' @export
#' @rdname macos_keychain

macos_item <- function(value, attributes = list(),
                       class = "generic_password") {
  stopifnot(
    class %in% macos_item_classes(),
    is_string(value),
    is_macos_attributes(attributes, class)
  )

  if (is.character(value)) value <- charToRaw(enc2utf8(value))

  structure(
    list(class = class, value = value, attributes = attributes),
    class = "oskeyring_macos_item"
  )
}

format_attr <- function(x) {
  type <- vapply(x, typeof, character(1))
  x <- lapply(x, format)
  x <- ifelse(type != "raw", x, paste0("[raw] ", format(as.list(x))))
  nc <- nchar(x)
  ifelse(type != "raw" | nc <= 60, x, paste(substr(x, 1, 56), "..."))
}

#' @export
format.oskeyring_macos_item <- function(x, ...) {
  attr <- x$attributes[sort(names(x$attributes))]
  c(
    paste0("<oskeyring_macos_item: ", x$class, ">"),
    paste0(" ", names(attr), ": ", format_attr(attr)),
    if (!is.null(x$value)) " value: <-- hidden -->"
  )
}

#' @export

print.oskeyring_macos_item <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}

#' @param item Keychain item, creted via [macos_item()] or returned
#' by oskeyking itself.
#' @param keychain Select an alternative keychain, instead of the default.
#' Not implemented yet.
#'
#' @export
#' @rdname macos_keychain

macos_item_add <- function(item, keychain = NULL) {
  os_check("macOS")
  stopifnot(
    inherits(item, "oskeyring_macos_item"),
    is_string(keychain) || is.null(keychain)
  )
  invisible(call_with_cleanup(oskeyring_macos_add, item, keychain))
}

#' @param class Type of items to search, see [macos_item_classes()] for
#' possible values.
#' @param attributes Narrow the search by indicating the attributes that
#' the found item or items should have.
#' @param match Condition the search in a variety of ways. For example, you
#' can limit the results to a specific number of items, control case
#' sensitivity when matching string attributes, etc. See 'Search parameters'
#' below.
#' @param return_data Whether to include the secret data in the
#' search result. If this is set to `TRUE`, then you'll have to set the
#' `limit` parameter (in the `match` argument) to a finite value.
#' If this is `TRUE`, then macOS will prompt you for passwords if necessary.
#' You might get multiple password prompts, if you set `limit` to a larger
#' than one value.
#'
#' @export
#' @rdname macos_keychain

macos_item_search <- function(class = "generic_password", attributes = list(),
                              match = list(), return_data = FALSE,
                              keychain = NULL) {
  os_check("macOS")
  stopifnot(
    class %in% macos_item_classes(),
    is_macos_attributes(attributes, class),
    is_macos_match(match),
    is_flag(return_data),
    is_string(keychain) || is.null(keychain)
  )
  call_with_cleanup(oskeyring_macos_search, class, attributes, match,
                    return_data, keychain)
}

#' @param update Named list specifying the new values of attributes.
#'
#' @export
#' @rdname macos_keychain

macos_item_update <- function(class = "generic_password", attributes = list(),
                              match = list(), update = list(), keychain = NULL) {
  os_check("macOS")
  stopifnot(
    class %in% macos_item_classes(),
    is_macos_attributes(attributes, class),
    is_macos_match(match),
    is_macos_attributes(update, class),
    is_string(keychain) || is.null(keychain)
  )

  invisible(
    call_with_cleanup(oskeyring_macos_update, class, attributes, match, update, keychain)
  )
}

#' @export
#' @rdname macos_keychain

macos_item_delete <- function(class = "generic_password", attributes = list(),
                              match = list(), keychain = NULL) {
  os_check("macOS")
  stopifnot(
    class %in% macos_item_classes(),
    is_macos_attributes(attributes, class),
    is_macos_match(match),
    is_string(keychain) || is.null(keychain)
  )

  invisible(
    call_with_cleanup(oskeyring_macos_delete, class, attributes, match, keychain)
  )
}

# ------------------------------------------------------------------------
# Access control
# ------------------------------------------------------------------------

# TODO

# ------------------------------------------------------------------------
# Keychains
# ------------------------------------------------------------------------

#' @export
#' @param keychain Keychain to use. `NULL` means the default one.
#' @param password Password to unlock the keychain, or new password to
#' set when creating a new keychain. May be `NULL` in interactive
#' sessions, to force a secure password dialog.
#' @rdname macos_keychain

macos_keychain_create <- function(keychain, password = NULL) {
  os_check("macOS")
  stopifnot(
    is_string(keychain),
    is_string(password) || is.null(password)
  )

  password <- password %||% ask_pass("Keychain password: ")
  file <- macos_keychain_file(keychain)
  invisible(call_with_cleanup(oskeyring_macos_keychain_create, file, password))
}

#' @param domain The preference domain from which you wish to retrieve
#' the keychain search list:
#' * `"all"`: include all keychains currently on the search list,
#' * `"user"`: user preference domain,
#' * `"system"`: system or daemon preference domain,
#' * `"common"`: keychains common to everyone,
#' * `"dynamic"`: dynamic search list (typically provided by removable
#' keychains such as smart cards).
#'
#' @export
#' @rdname macos_keychain

macos_keychain_list <- function(domain = c("all", "user", "system",
                                           "common", "dynamic")) {
  os_check("macOS")
  domain <- match.arg(domain)
  ret <- call_with_cleanup(oskeyring_macos_keychain_list, domain)
  data.frame(
    stringsAsFactors = FALSE,
    path = ret[[1]],
    is_unlocked = ret[[2]],
    is_readable = ret[[3]],
    is_writeable = ret[[4]]
  )
}

#' @export
#' @rdname macos_keychain

macos_keychain_delete <- function(keychain) {
  os_check("macOS")
  stopifnot(
    is_string(keychain)
  )
  if (grepl("^login\\.keychain", basename(keychain))) {
    stop("Refusing to delete the login keychain")
  }
  if (grepl("^System\\.keychain", basename(keychain))) {
    stop("Refusing to delete the system keychain")
  }
  file <- macos_keychain_file(keychain)
  invisible(call_with_cleanup(oskeyring_macos_keychain_delete, file))
}

#' @export
#' @rdname macos_keychain

macos_keychain_lock <- function(keychain = NULL) {
  os_check("macOS")
  stopifnot(
    is_string(keychain) || is.null(keychain)
  )
  file <- macos_keychain_file(keychain)
  invisible(call_with_cleanup(oskeyring_macos_keychain_lock, file))
}

#' @export
#' @rdname macos_keychain

macos_keychain_unlock <- function(keychain = NULL, password = NULL) {
  os_check("macOS")
  stopifnot(
    is_string(keychain) || is.null(keychain),
    is_string(password) || is.null(password)
  )

  password <- password %||% ask_pass("Password to unlock keychain: ")
  file <- macos_keychain_file(keychain)
  invisible(call_with_cleanup(oskeyring_macos_keychain_unlock, file, password))
}

#' @export
#' @rdname macos_keychain

macos_keychain_is_locked <- function(keychain = NULL) {
  os_check("macOS")
  stopifnot(
    is_string(keychain) || is.null(keychain)
  )
  file <- macos_keychain_file(keychain)
  call_with_cleanup(oskeyring_macos_keychain_is_locked, file)
}

#' @export
#' @rdname macos_keychain

macos_item_attr <- function() {
  list(
    generic_password = list(
#      access,
#      access_control,
#      access_group,
#      accessible,
      creation_date = paste0(
        "[.POSIXct(1)][read-only] The date the item was created."),
      modification_date = paste0(
        "[.POSIXct(1)][read-only] The last time the item was updated."),
      description = paste0(
        "[character(1)] User-visible string describing this kind of",
        "item (for example, 'Disk image password')."),
      comment = "[character(1)] User-editable comment for this item.",
#      "creator",
#      "type",
      label = "[character(1)] User-visible label for this item.",
      is_invisible = paste0(
        "[logical(1)] `TRUE` if the item is invisible (that is, should ",
        "not be displayed)."),
      is_negative = paste0(
        "[logical(1)] Indicates whether there is a valid password ",
        "associated with this keychain item. This is useful if your ",
        "application doesn't want a password for some particular service ",
        "to be stored in the keychain, but prefers that it always be ",
        "entered by the user."),
      account = "[character(1)][key] Account name.",
      service = paste0(
        "[character(1)][key] The service associated with this item."),
      generic = "[character(1)] User-defined attribute.",
      synchronizable = paste0(
        "[logical(1)] Indicates whether the item in question is ",
        "synchronized to other devices through iCloud.")
    ),
    internet_password = list(
#      access,
#      access_group,
#      accessible,
      creation_date = paste0(
        "[.POSIXct(1)][read-only] The date the item was created."),
      modification_date = paste0(
        "[.POSIXct(1)][read-only] The last time the item was updated."),
      description = paste0(
        "[character(1)] User-visible string describing this kind of",
        "item (for example, 'Disk image password')."),
      comment = "[character(1)] User-editable comment for this item.",
#      "creator",
#      "type",
      label = "[character(1)] User-visible label for this item.",
      is_invisible = paste0(
        "[logical(1)] `TRUE` if the item is invisible (that is, should ",
        "not be displayed)."),
      is_negative = paste0(
        "[logical(1)] Indicates whether there is a valid password ",
        "associated with this keychain item. This is useful if your ",
        "application doesn't want a password for some particular service ",
        "to be stored in the keychain, but prefers that it always be ",
        "entered by the user."),
      account = "[character(1)][key] Account name.",
      synchronizable = paste0(
        "[logical(1)] Indicates whether the item in question is ",
        "synchronized to other devices through iCloud."),
      security_domain = "[character(1)][key] The item's security domain.",
      server = paste0(
        "[character(1)][key] Contains the server's domain name or IP ",
        "address."),
      protocol = "[character(1)][key] The protocol for this item.",
      authentication_type = "character[1][key] Authentication type.",
      port = "[integer(1)][key] Internet port number.",
      path = paste0(
        "[character(1)][key] A path, typically the path component of ",
        "the URL")
    )
  )
}

#' @export
#' @rdname macos_keychain

macos_item_match_options <- function() {
  list(
    ## TODO: authentication_context,
    ## TODO: how does use_authentication_ui work?
    ## TODO: use_operation_prompt
    ## policy,
    ## issuers,
    ## email_address_if_present,
    ## subject_contains,
    ## subject_starts_with,
    ## subject_ends_with,
    ## subject_whole_string,
    ## TODO: case_insensitive does not work? Only for certs?
    ## TODO: diacritic_insensitive similar
    ## TODO: width_insensitive similar
    ## trusted_only,
    ## valid_on_date,
    limit = paste0(
      "[numeric(1)] This value specifies the maximum number of results ",
      "to return or otherwise act upon. Use `Inf` to specify all ",
      "matching items.")
  )
}

# ------------------------------------------------------------------------
# Internals
# ------------------------------------------------------------------------

macos_keychain_file <- function(keychain = NULL) {
  if (!is.null(keychain)) {
    enc2utf8(normalizePath(keychain, mustWork = FALSE))
  }
}

item_list <- function(x) {
  nms <- names(x)
  x <- gsub("[", "\\[", x, fixed = TRUE)
  x <- gsub("]", "\\]", x, fixed = TRUE)
  paste0("* `", nms, "`: ", x, collapse = "\n")
}

is_macos_attributes <- function(attr, class) {
  if (!is_named_list(attr)) return(FALSE)
  attr <- macos_item_attr()[[class]]
  bad <- setdiff(names(attributes), names(attr))
  if (length(bad)) {
    stop("Unknown attributes for `", class, "`:",
         paste0("`", bad, "`", collapse = ", "))
  }
  TRUE
}

is_macos_match <- function(x) {
  if (!is_named_list(x)) return(FALSE)
  mtch <- macos_item_match_options()
  bad <- setdiff(names(x), names(mtch))
  if (length(bad)) {
    stop("Unknown attributes for `", class, "`:",
         paste0("`", bad, "`", collapse = ", "))
  }
  TRUE
}

darwin_version <- function() {
  info <- Sys.info()
  if (info[["sysname"]] != "Darwin")
    stop("Not macOS")
  package_version(info[["release"]])
}
