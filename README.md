
# oskeyring

> Raw System Credential Store Access from R

<!-- badges: start -->

[![](http://www.r-pkg.org/badges/version/oskeyring)](http://www.r-pkg.org/pkg/oskeyring)
[![CRAN RStudio mirror
downloads](http://cranlogs.r-pkg.org/badges/oskeyring)](http://www.r-pkg.org/pkg/oskeyring)

<!-- badges: end -->

Raw System Credential Store Access from R

## Installation

Install the package from CRAN:

``` r
install.packages("oskeyring")
```

## Usage

``` r
library(oskeyring)
```

Most oskeyring functions are not portable, on only work on one operating
system (OS). The functions that do not use the system credential store
can be used on all OSes. E.g. `macos_item()` and `windows_item()` are
portable. Calling a function on the wrong OS will throw a
`oxkeyring_bad_os_error` error.

oskeyring follows the API of the OS closely, and it has a different set
of functions on Windows and macOS. E.g. the macOS API can search for
KeyChain items based on item attributes, but there is no similar API on
Windows, so oskeyring does not have a `windows_item_search()` function.

### macOS

#### Keychain items

oskeyring uses the [KeyChain
API](https://developer.apple.com/documentation/security/keychain_services)
on macOS. macOS keychains can store various classes of items. The item
classes supported by oskeyring:

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

### Windows Credential Store

TODO

## License

MIT © [RStudio](https://github.com/rstudio)
