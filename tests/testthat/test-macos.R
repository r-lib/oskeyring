
if (packageVersion("testthat") <= "2.5.0") {
  testthat::teardown(test_cleanup_macos())
} else {
  withr::defer(test_cleanup_macos(), teardown_env())
}

test_that("macos_item_classes", {
  expect_true(is.character(macos_item_classes()))
})

test_that("macos_item", {
  it <- macos_item("qwerty123", list(service = "service"))
  expect_s3_class(it, "oskeyring_macos_item")
})

test_that("format.oskeyring_macos_item", {
  it <- macos_item("qwerty123", list(service = "service"))
  fmt <- format(it)
  expect_false(any(grepl("qwerty123", fmt)))
})

test_that("print.oskeyring_macos_item", {
  it <- macos_item("qwerty123", list(service = "service"))
  out <- capture.output(print(it))
  expect_false(any(grepl("qwerty123", out)))
})

osk_test_that("macos", "macos_item_add", {
  service <- random_name()
  it <- macos_item(
    "secret!",
    list(service = service, description = "foo", comment = "oskeyring-test")
  )
  expect_null(macos_item_add(it))

  eit <- macos_item_search("generic_password", list(service = service))
  expect_equal(length(eit), 1)
  expect_equal(eit[[1]]$attributes$description, "foo")

  expect_null(
    macos_item_delete("generic_password", list(service = service))
  )
  expect_equal(macos_item_search(, list(service = service)), list())

  it2 <- macos_item(
    "secret2!",
    list(server = service, description = "bar", comment = "oskeyring-test"),
    "internet_password"
  )
  expect_null(macos_item_add(it2))

  eit2 <- macos_item_search("internet_password", list(server = service))
  expect_equal(length(eit2), 1)
  expect_equal(eit2[[1]]$attributes$description, "bar")

  expect_null(
    macos_item_delete("internet_password", list(server = service))
  )
  expect_equal(
    macos_item_search("internet_password", list(server = service)),
    list()
  )
})

osk_test_that("macos", "unsupported os", {
  it <- windows_item("foo", "bar")
  expect_error(
    windows_item_write(it),
    class = "oskeyring_bad_os_error"
  )
})

osk_test_that("macos", "macos_item_update", {
  service <- random_name()
  it <- macos_item(
    "secret!",
    list(service = service, description = "foo", comment = "oskeyring-test")
  )
  expect_null(macos_item_add(it))

  service2 <- paste0(service, "-2")
  macos_item_update(
    "generic_password",
    attributes = list(service = service),
    update = list(service = service2, description = "bar")
  )

  eit <- macos_item_search("generic_password", list(service = service2))
  expect_equal(length(eit), 1)
  expect_equal(eit[[1]]$attributes$description, "bar")
})

osk_test_that("macos", "keychains", {
  new <- paste0(
    "~/Library/Keychains/oskeyking-test-",
    basename(tempfile()),
    ".keychain-db"
  )
  expect_null(macos_keychain_create(new, password = "secret"))
  lst <- macos_keychain_list()
  expect_true(any(grepl(basename(new), lst$path, fixed = TRUE)))
  expect_null(macos_keychain_lock(new))
  expect_true(macos_keychain_is_locked(new))
  expect_null(macos_keychain_unlock(new, password = "secret"))
  expect_false(macos_keychain_is_locked(new))
})

osk_test_that("macos", "will not delete login/system keychain", {
  expect_error(
    macos_keychain_delete("foo/bar/login.keychain"),
    "Refusing to delete"
  )
  expect_error(
    macos_keychain_delete("foo/bar/System.keychain"),
    "Refusing to delete"
  )
})

test_that("item_list", {
  expect_equal(
    item_list(c(foo = "bar", foobar = "baz")),
    "* `foo`: bar\n* `foobar`: baz"
  )
})

test_that("is_macos_attributes", {
  expect_false(is_macos_attributes(list("a", "b")))
  expect_error(
    is_macos_attributes(list(foo = "bar"), "generic_password"),
    "Unknown attributes"
  )
})

test_that("is_macos_match", {
  expect_false(is_macos_match(list("a", "b")))
  expect_error(
    is_macos_match(list(foo = "bar")),
    "Unknown match parameters"
  )
})
