
#' Query and manipulate the macOS Keychain
#'
#' @description
#' `macos_item_*` functions add, delete, update and search Keychain items.
#'
#' `macos_keychain_*` functions create, delete, list, lock, unlock
#' keychains.
#'
#' @details
#' ## Keychain items
#'
#' TODO
#'
#' ### Attributes for different Keychain item classes
#'
#' TODO
#'
#' ## Keychains
#'
#'
#' TODO
#'
#' @export
#' @rdname macos_keychain
#' @name macos_keychain

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
  x <- ifelse(type != "raw", x, paste0("[raw] ", x))
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
  stopifnot(
    inherits(item, "oskeyring_macos_item"),
    is.null(keychain)
  )
  invisible(call_with_cleanup(oskeyring_macos_add, item, keychain))
}

#' @details
#' ## Search Parameters
#'
#' TODO
#'
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
  stopifnot(
    class %in% macos_item_classes(),
    is_macos_attributes(attributes, class),
    is_macos_match(match),
    is_flag(return_data),
    is.null(keychain)
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
  stopifnot(
    class %in% macos_item_classes(),
    is_macos_attributes(attributes, class),
    is_macos_match(match),
    is_macos_attributes(update, class),
    is.null(keychain)
  )
  call_with_cleanup(oskeyring_macos_update, class, attributes, match, update, keychain)
}

#' @export
#' @rdname macos_keychain

macos_item_delete <- function(class = "generic_password", attributes = list(),
                              match = list(), keychain = NULL) {
  stopifnot(
    class %in% macos_item_classes(),
    is_macos_attributes(attributes, class),
    is_macos_match(match),
    is.null(keychain)
  )
  call_with_cleanup(oskeyring_macos_delete, class, attributes, match, keychain)
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
  stopifnot(
    is_string(keychain),
    is_string(password) || is.null(password)
  )

  password <- password %||% ask_pass("Keychain password: ")
  file <- macos_keychain_file(keychain)
  call_with_cleanup(oskeyring_macos_keychain_create, file, password)
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
  stopifnot(
    is_string(keychain),
  )
  if (grepl("^login\\.keychain", basename(keychain))) {
    stop("Refusing to delete the login keychain")
  }
  if (grepl("^System\\.keychain", basename(keychain))) {
    stop("Refusing to delete the system keychain")
  }
  file <- macos_keychain_file(keychain)
  call_with_cleanup(oskeyring_macos_keychain_delete, file)
}

#' @export
#' @rdname macos_keychain

macos_keychain_lock <- function(keychain = NULL) {
  stopifnot(
    is_string(keychain) || is.null(keychain)
  )
  file <- macos_keychain_file(keychain)
  call_with_cleanup(oskeyring_macos_keychain_lock, file)
}

#' @export
#' @rdname macos_keychain

macos_keychain_unlock <- function(keychain = NULL, password = NULL) {
  stopifnot(
    is_string(keychain) || is.null(keychain),
    is_string(password) || is.null(password)
  )

  password <- password %||% ask_pass("Password to unlock keychain: ")
  file <- macos_keychain_file(keychain)
  call_with_cleanup(oskeyring_macos_keychain_unlock, file, password)
}

#' @export
#' @rdname macos_keychain

macos_keychain_is_locked <- function(keychain = NULL) {
  stopifnot(
    is_string(keychain) || is.null(keychain),
  )
  file <- macos_keychain_file(keychain)
  call_with_cleanup(oskeyring_macos_keychain_is_locked, file)
}

#' @export
#' @rdname macos_keychain

macos_keychain_file <- function(keychain = NULL) {
  if (!is.null(keychain)) {
    enc2utf8(normalizePath(keychain, mustWork = FALSE))
  }
}

# ------------------------------------------------------------------------
# Internals
# ------------------------------------------------------------------------

# TODO: create these from the C data to avoid duplication

macos_attr <- function() {
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

is_macos_attributes <- function(attr, class) {
  if (!is_named_list(attr)) return(FALSE)
  attr <- macos_attr()[[class]]
  bad <- setdiff(names(attributes), names(attr))
  if (length(bad)) {
    stop("Unknown attributes for `", class, "`:",
         paste0("`", bad, "`", collapse = ", "))
  }
  TRUE
}

macos_match_options <- function() {
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
    case_insensitive = paste0(
      "[logical(1)] If this value is `TRUE`, or if this option is not ",
      "provided, then case-sensitive string matching is performed"),
    diacritic_insensitive = paste0(
      "[logical(1)] If this value is `FALSE`, or if this option is not ",
      "provided, then diacritic-sensitive string matching is performed."),
    width_insensitive = paste0(
      "[logical(1)] If this value is `FALSE`, or if this option is not ",
      "provided, then width-sensitive string matching is performed."),
    ## trusted_only,
    ## valid_on_date,
    limit = paste0(
      "[logical(1)] This value specifies the maximum number of results ",
      "to return or otherwise act upon. Use `Inf` to specify all ",
      "matching items")
  )
}

is_macos_match <- function(x) {
  if (!is_named_list(x)) return(FALSE)
  mtch <- macos_match_options()
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
