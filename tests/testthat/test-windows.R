if (packageVersion("testthat") <= "2.5.0") {
  testthat::teardown(test_cleanup_windows())
} else {
  withr::defer(test_cleanup_windows(), teardown_env())
}

test_that("windows_item_types", {
  expect_true(is.character(windows_item_types()))
})

test_that("windows_item", {
  it <- windows_item("secret", "target")
  expect_s3_class(it, "oskeyring_windows_item")
})

test_that("format.windows_item", {
  attr <- list(key1 = "value1", key2 = "value2")
  it <- windows_item("qwerty123", "target", attributes = attr)
  fmt <- format(it)
  expect_false(any(grepl("qwerty123", fmt)))
  expect_true(any(grepl("key1.*value1", fmt)))
  expect_true(any(grepl("key2.*value2", fmt)))
})

test_that("print.windows_item", {
  it <- windows_item("qwerty123", "target")
  out <- capture.output(print(it))
  expect_false(any(grepl("qwerty123", out)))
})

osk_test_that("windows", "windows_item_write", {
  target <- random_name()
  it <- windows_item(
    "secret!",
    target,
    attributes = list(key1 = charToRaw("value1"))
  )
  expect_null(windows_item_write(it))

  eit <- windows_item_read(target)
  expect_s3_class(eit, "oskeyring_windows_item")
  expect_equal(
    iconv(list(eit$credential_blob), "UTF-16LE", "UTF-8"),
    "secret!"
  )

  it2 <- windows_item(NULL, target)
  expect_null(windows_item_write(it2, preserve = TRUE))
  eit2 <- windows_item_read(target)

  lst <- windows_item_enumerate("oskeyring-test-*")
  tgs <- vapply(lst, "[[", character(1), "target_name")
  expect_true(target %in% tgs)

  expect_null(windows_item_delete(target))

  expect_error(
    windows_item_read(target),
    "Windows credential store error"
  )
})

osk_test_that("windows", "windows_item_write #2", {
  it <- windows_item("x", random_name())
  it$attributes <- list(x = 1L)
  expect_error(
    windows_item_write(it)
  )
})

osk_test_that("windows", "unsupported os", {
  it <- macos_item("foobar")
  expect_error(
    macos_item_add(it),
    class = "oskeyring_bad_os_error"
  )
})
