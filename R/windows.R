
#' @export

windows_item_types <- function() {
  c("generic", "domain_password", "domain_certificate",
    "domain_visible_password")
}

#' @export

windows_item <- function(credential_blob, target_name,
                         type = "generic", comment = NULL,
                         persist = c("local_machine", "session",
                           "enterprise"), attributes = list(),
                         target_alias = NULL, username = NULL,
                         encoding = "UCS-2LE") {

  persist <- match.arg(persist)
  stopifnot(
    is_string_or_raw(credential_blob),
    is_string(target_name),
    is_string(type) && type %in% windows_item_types(),
    is.null(comment) || is_string(comment),
    is_named_list(attributes) &&
      all(vapply(attributes, function(x) is_string_or_raw(x), logical(1))),
    is.null(target_alias) || is_string(target_alias),
    is.null(username) || is_string(username),
    is_string(encoding)
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
      username = username,
      encoding = encoding
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
    if (!is.null(x$attributes)) {
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

#' @export

windows_item_read <- function(target_name, type = "generic") {
  stopifnot(
    is_string(target_name),
    is_string(type) && type %in% windows_item_types()
  )

  target_name <- to_ucs2(target_name)
  item <- call_with_cleanup(oskeyring_windows_read, target_name, type)

  windows_item_from_ucs2(item)
}

#' @export

windows_item_write <- function(item, preserve = FALSE) {
  stopifnot(
    inherits(item, "oskeyring_windows_item"),
    is_flag(preserve)
  )

  encode <- function(x, to = item$encoding) {
    if (is.character(x)) {
      iconv(x, to = to, toRaw = TRUE)[[1]]
    } else if (is.raw(x)) {
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

#' @export

windows_item_delete <- function(target_name, type = "generic") {
  stopifnot(
    is_string(target_name),
    is_string(type) && type %in% windows_item_types()
  )

  target_name <- to_ucs2(target_name)
  invisible(call_with_cleanup(oskeyring_windows_delete, target_name, type))
}

#' @export

windows_item_enumerate <- function(filter = NULL, all = FALSE) {
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
