
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

#' @export
format.oskeyring_macos_item <- function(x, ...) {
  c(
    paste0("<oskeyring_macos_item: ", x$class, ">"),
    paste0(" ", names(x$attributes), ": ", x$attributes)
  )
}

#' @export

print.oskeyring_macos_item <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}

#' @param item Keychain item, creted via [macos_item()] or returned
#' by oskeyking itself.
#' @param keychain Which keychain to use. `NULL` means the default one.
#'
#' @export
#' @rdname macos_keychain

macos_item_add <- function(item, keychain = NULL) {
  stopifnot(
    inherits(item, "oskeyring_macos_item"),
    is.null(keychain)
  )
  call_with_cleanup(oskeyring_macos_add, item, keychain)
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
#'
#' @export
#' @rdname macos_keychain

macos_item_search <- function(class = "generic_password", attributes = list(),
                              match = list(), keychain = NULL) {
  stopifnot(
    class %in% macos_item_classes(),
    is_macos_attributes(attributes, class),
    is_macos_match(match),
    is.null(keychain)
  )
  call_with_cleanup(oskeyring_macos_search, class, attributes, match, keychain)
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

#' @export
#' @rdname macos_keychain

macos_keychain_list <- function() {
  res <- call_with_cleanup(oskeyring_macos_keychain_list)
  data.frame(
    keyring = res[[1]],
    num_secrets = res[[2]],
    locked = res[[3]],
    stringsAsFactors = FALSE
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

macos_attr <- function() {
  list(
    generic_password = list(
#      access,
#      access_control,
#      access_group,
#      accessible,
#      creation_date,
#      modification_date,
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
      account = "[character(1)] Account name.",
      service = "[character(1)] The service associated with this item.",
      generic = "[character(1)] User-defined attribute.",
      synchronizable = paste0(
        "[logical(1)] Indicates whether the item in question is ",
        "synchronized to other devices through iCloud.")
    ),
    internet_password = list(
#      access,
#      access_group,
#      accessible,
#      creation_date,
#      modification_date,
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
      account = "[character(1)] Account name.",
      synchronizable = paste0(
        "[logical(1)] Indicates whether the item in question is ",
        "synchronized to other devices through iCloud."),
      security_domain = "[character(1)] The item's security domain.",
      server = paste0(
        "[character(1)] Contains the server's domain name or IP address."),
      protocol = "[character(1)] The protocol for this item.",
      authentication_type = "character[1] Authentication type.",
      port = "[integer(1)] Internet port number.",
      path = paste0(
        "[character(1)] A path, typically the path component of the URL")
    )
  )
}

macos_to_camel <- function(names) {
  map <- c(
    generic_password = "GenericPassword",
    internet_password = "InternetPassword",

#    access = "Access",
#    access_control = "AccessControl",
#    access_group = "AccessGroup",
#    accessible = "Accessible",
    account = "Account",
    authentication_type = "AuthenticationType",
    comment = "Comment",
#    creation_date = "CreationDate",
#    creator = "Creator",
    description = "Description",
    generic = "Generic",
    is_invisible = "IsInvisible",
    is_negative = "IsNegative",
    label = "Label",
#    modification_date = "ModificationDate",
    path = "Path",
    port = "Port",
    protocol = "Protocol",
    service = "Service",
    security_domain = "SecurityDomain",
    server = "Server",
    synchronizable = "Synchronizable",
#    type = "Type"
  )

  map[names]
}

macos_to_lower <- function(names) {
  tolower(names)
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

is_macos_match <- function(x) {
  if (!is_named_list(x)) return(FALSE)
  # TODO
  TRUE
}

darwin_version <- function() {
  info <- Sys.info()
  if (info[["sysname"]] != "Darwin")
    stop("Not macOS")
  package_version(info[["release"]])
}
