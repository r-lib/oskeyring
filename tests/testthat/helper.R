
is_ci <- function() {
  Sys.getenv("CI", "") != ""
}

random_name <- function() {
  paste0("oskeyring-test-", basename(tempfile()))
}

osk_test_that <- function(os, desc, code) {
  if (is_ci() && tolower(os) == get_os()) {
    testthat::test_that(desc, { code })
  }
}

test_cleanup_macos <- function() {
  if (is_ci() && tolower(get_os()) == "macos") {
    empty_error <- function(x) grepl("not be found", x$message)
    tryCatch(
      macos_item_delete(
        "generic_password",
        attributes = list(comment = "oskeyring-test")
      ),
      error = function(err) if (!empty_error(err)) print(err)
    )
    tryCatch(
      macos_item_delete(
        "internet_password",
        attributes = list(comment = "oskeyring-test")
      ),
      error = function(err) if (!empty_error(err)) print(err)
    )
    tryCatch(
      {
        lst <- macos_keychain_list()
        tst <- grep("oskeyking-test", lst$path, value = TRUE)
        for (fn in tst) try(macos_keychain_delete(fn))
      },
      error = function(err) print(err)
    )
  }
}

test_cleanup_windows <- function() {
  if (is_ci() && tolower(get_os()) == "windows") {
    tryCatch(
      {
        its <- windows_item_enumerate("oskeyring-test-*")
        for (it in its) {
          try(windows_item_delete(it$target_name, it$type))
        }
      },
      error = function(err) print(err)
    )
  }
}
