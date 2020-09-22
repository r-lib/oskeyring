
`%||%` <- function(l, r) if (is.null(l)) r else l

is_string <- function(x) {
  is.character(x) && length(x) == 1 && !is.na(x)
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
