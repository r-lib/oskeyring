
# oskeyring

> Raw System Credential Store Access from R

<!-- badges: start -->

[![R-CMD-check](https://github.com/r-lib/oskeyring/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/r-lib/oskeyring/actions/workflows/R-CMD-check.yaml)
[![Codecov test
coverage](https://codecov.io/gh/r-lib/oskeyring/branch/main/graph/badge.svg)](https://app.codecov.io/gh/r-lib/oskeyring?branch=main)
<!-- badges: end -->

## Features

- Windows and macOS support. Read, write, list and search the system
  credential store.
- Generic credentials, domain passwords, domain certificates on Windows.
- Generic passwords and internet passwords on macOS.
- Multiple keychains on macOS.

## Related

- The keyring R package provides a portable system keyring API for all
  platforms, and also supports multiple backends:
  <https://github.com/r-lib/keyring>

## Installation

Install the package from CRAN:

``` r
install.packages("oskeyring")
```

## Usage

``` r
library(oskeyring)
```

Most oskeyring functions are not portable, and only work on one
operating system (OS). The functions that do not use the system
credential store can be used on all OSes. E.g. `macos_item()` and
`windows_item()` are portable. Calling a function on the wrong OS will
throw an `oskeyring_bad_os_error` error.

oskeyring follows the API of the OS closely, and it has a different set
of functions on Windows and macOS. E.g. the macOS API can search for
keychain items based on item attributes, but there is no similar API on
Windows, so oskeyring does not have a `windows_item_search()` function.

### Windows Credential Store

oskeyring uses the API defined in
[`wincred.h`](https://learn.microsoft.com/en-us/windows/win32/api/wincred/)
on Windows. The Windows credential store contains various credential
types. The ones supported by oskeyring are:

``` r
windows_item_types()
```

    #> [1] "generic"                 "domain_password"        
    #> [3] "domain_certificate"      "domain_visible_password"

`windows_item_write()` adds or updates a credential in the credential
store. It takes objects created with `windows_item()` :

``` r
it <- windows_item("secret", "my-host-password")
it
```

    #> <oskeyring_windows_item: generic>
    #>  target_name: my-host-password
    #>  persist: local_machine
    #>  credential_blob: <-- hidden -->

``` r
windows_item_write(it)
```

`windows_item_read()` reads a credential from the credential store, the
return value includes the secret as well:

``` r
windows_item_read("my-host-password")
```

``` r
#> <oskeyring_windows_item: generic>
#>  target_name: my-host-password
#>  persist: local_machine
#>  credential_blob: <-- hidden -->
```

`windows_item_enumerate()` lists all credentials that match a prefix.

`windows_item_delete()` deletes a credential.

See more in the manual: `?windows_credentials`.

### macOS Keychain Services

#### Keychain items

oskeyring uses the [Keychain
API](https://developer.apple.com/documentation/security/keychain_services)
on macOS. macOS keychains can store various classes of items. The item
classes supported by oskeyring are:

``` r
macos_item_classes()
```

    #> [1] "generic_password"  "internet_password"

`macos_item_add()` adds a new item to a keychain. It takes objects
created with `macos_item()`:

``` r
it <- macos_item(
  "secret",
  list(service = "My service", account = "Gabor"),
  class = "generic_password"
)
it
```

    #> <oskeyring_macos_item: generic_password>
    #>  account: Gabor
    #>  service: My service
    #>  value: <-- hidden -->

Items contain the secret itself, and a set of attributes, that depends
on the item class. See `?macos_keychain` for the list of attributes for
each class.

``` r
macos_item_add(it)
```

`macos_item_search()` searches for a keychain item:

``` r
macos_item_search(attributes = list(service = "My service"))
```

``` r
#> [[1]]
#> <oskeyring_macos_item: generic_password>
#>  account: Gabor
#>  creation_date: 2020-10-21 10:01:44
#>  label: My service
#>  modification_date: 2020-10-21 10:01:44
#>  service: My service
```

It does not return the secret itself, unless it is called with
`return_data = TRUE`. This possibly prompts the user for a password.

`macos_item_update()` updates the attributes of existing Keychain items.

`macos_item_delete()` deletes one or more Keychain items.

#### Keychains

macOS supports multiple keychains. There is always a default keychain,
and this is what oskeyring uses by default as well. There is also a
keychain search list, where secrets are looked up by default, and this
can contain multiple keychains.

`macos_item_*()` functions have a `keychain` argument to direct or
restrict the operation to a specific keychain.

`macos_keychain_create()` creates a new keychain.

`macos_keychain_list()` lists all keychains on the search list.

See more about macOS keychains in the manual: `?macos_keychain`.

## Code of Conduct

Please note that the oskeyring project is released with a [Contributor
Code of
Conduct](https://r-lib.github.io/oskeyring/CODE_OF_CONDUCT.html). By
contributing to this project, you agree to abide by its terms.

## License

MIT © [RStudio](https://github.com/rstudio)
