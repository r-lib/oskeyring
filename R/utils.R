
utils::globalVariables(c(
  "oskeyring_macos_add",
  "oskeyring_macos_delete",
  "oskeyring_macos_search",
  "oskeyring_macos_update",
  "oskeyring_macos_keychain_create",
  "oskeyring_macos_keychain_delete",
  "oskeyring_macos_keychain_is_locked",
  "oskeyring_macos_keychain_list",
  "oskeyring_macos_keychain_lock",
  "oskeyring_macos_keychain_unlock",
  "oskeyring_windows_write",
  "oskeyring_windows_read",
  "oskeyring_windows_delete",
  "oskeyring_windows_enumerate"
))

`%||%` <- function(l, r) if (is.null(l)) r else l

is_string <- function(x) {
  is.character(x) && length(x) == 1 && !is.na(x)
}

is_string_or_raw <- function(x) {
  is_string(x) || is.raw(x)
}

is_flag <- function(x) {
  is.logical(x) && length(x) == 1 && !is.na(x)
}

is_named_list <- function(x) {
  nms <- names(x)
  is.list(x) && length(nms) == length(x) && !any(is.na(nms)) &&
    !any(nms == "")
}

ask_pass <- function(prompt = "Password: ") {
  res <- askpass::askpass(prompt)
  res <- res %||% askpass::askpass(prompt)
  enc2utf8(res)
}

os_check <- function(which = c("macOS", "Windows", "Linux")) {
  which <- match.arg(which)
  os <- get_os()
  if (os != tolower(which)) {
    stop("Unsupported OS. This function only works on ", which, ".")
  }
}

get_os <- function() {
  if (.Platform$OS.type == "windows") {
    "win"
  } else if (Sys.info()["sysname"] == "Darwin") {
    "macos"
  } else if (Sys.info()[["sysname"]] == "Linux") {
    "linux"
  } else {
    "other"
  }
}

lapply_with_names <- function(X, FUN, ...) {
  structure(lapply(X, FUN, ...), names = names(X))
}

last_character <- function(x) {
  substr(x, nchar(x), nchar(x))
}
