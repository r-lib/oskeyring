
call_with_cleanup <- function(ptr, ...) {
  .Call(cleancall_call, pairlist(ptr, ...), parent.frame())
}

globalVariables("cleancall_call")
