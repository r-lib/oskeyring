# Query and manipulate the macOS Keychain

`macos_item_*` functions add, delete, update and search Keychain items.

`macos_keychain_*` functions create, delete, list, lock, unlock
keychains.

`macos_item_classes()` lists the supported Keychain item classes.
`macos_item_attr()` lists the supported attributes for these classes.
`macos_item_match_options()` lists the options supported by the `match`
argument of `macos_item_search()`.

## Usage

``` r
macos_item_classes()

macos_item(value, attributes = list(), class = "generic_password")

macos_item_add(item, keychain = NULL)

macos_item_search(
  class = "generic_password",
  attributes = list(),
  match = list(),
  return_data = FALSE,
  keychain = NULL
)

macos_item_update(
  class = "generic_password",
  attributes = list(),
  match = list(),
  update = list(),
  keychain = NULL
)

macos_item_delete(
  class = "generic_password",
  attributes = list(),
  match = list(),
  keychain = NULL
)

macos_keychain_create(keychain, password = NULL)

macos_keychain_list(domain = c("all", "user", "system", "common", "dynamic"))

macos_keychain_delete(keychain)

macos_keychain_lock(keychain = NULL)

macos_keychain_unlock(keychain = NULL, password = NULL)

macos_keychain_is_locked(keychain = NULL)

macos_item_attr()

macos_item_match_options()
```

## Arguments

- value:

  Value of the item, a password, key or certificate. It must a raw
  vector or a string. If it is a string, then it is converted to UTF-8.

- attributes:

  Narrow the search by indicating the attributes that the found item or
  items should have.

- class:

  Type of items to search, see `macos_item_classes()` for possible
  values.

- item:

  Keychain item, creted via `macos_item()` or returned by oskeyking
  itself.

- keychain:

  Keychain to use. `NULL` means the default one.

- match:

  Condition the search in a variety of ways. For example, you can limit
  the results to a specific number of items, control case sensitivity
  when matching string attributes, etc. See 'Search parameters' below.

- return_data:

  Whether to include the secret data in the search result. If this is
  set to `TRUE`, then you'll have to set the `limit` parameter (in the
  `match` argument) to a finite value. If this is `TRUE`, then macOS
  will prompt you for passwords if necessary. You might get multiple
  password prompts, if you set `limit` to a larger than one value.

- update:

  Named list specifying the new values of attributes.

- password:

  Password to unlock the keychain, or new password to set when creating
  a new keychain. May be `NULL` in interactive sessions, to force a
  secure password dialog.

- domain:

  The preference domain from which you wish to retrieve the keychain
  search list:

  - `"all"`: include all keychains currently on the search list,

  - `"user"`: user preference domain,

  - `"system"`: system or daemon preference domain,

  - `"common"`: keychains common to everyone,

  - `"dynamic"`: dynamic search list (typically provided by removable
    keychains such as smart cards).

## Value

`macos_item_classes()` returns a character vector, the names of the
supported keychain item classes.

`macos_item()` returns a new `oskeyring_macos_item` object.

`macos_item_add()` returns `NULL`, invisibly.

`macos_item_search()` returns a list of keychain items.

`macos_item_update()` returns `NULL`, invisibly.

`macos_item_delete()` returns `NULL`, invisibly.

`macos_keychain_create()` returns `NULL`, invisibly.

`macos_keychain_list()` returns a data frame with columns:

- `path`: Path to the file of the keychain.

- `is_locked`: Whether the keychain is locked.

- `is_readable`: Whether the keychain is readable by the user.

- `is_writeable`: Whether the keychain is writeable by the user.

`macos_keychain_delete()` returns `NULL`, invisibly.

`macos_keychain_lock()` returns `NULL`, invisibly.

`macos_keychain_unlock()` returns `NULL`, invisibly.

`macos_keychain_is_locked()` returns `TRUE` or `FALSE`.

`macos_item_attr()` returns a list of lists of character scalars, the
description of keychain item attributes, for each keychain item class.

`macos_item_match_options()` returns a list of character scalars, the
description of the supported match options.

## Keychain items

`macos_item_classes()` returns the currently supported Keychain item
classes.

    macos_item_classes()
    #> [1] "generic_password"  "internet_password"

`macos_item()` creates a new Keychain item. See the next section about
the attributes that are supported for the various item types.

    it <- macos_item("secret", list(service = "My service", account = "Gabor"))
    it
    #> <oskeyring_macos_item: generic_password>
    #>  account: Gabor
    #>  service: My service
    #>  value: <-- hidden -->

`macos_item_add()` adds an item to the keychain. If there is already an
item with the same primary keys, then it will error.

    macos_item_add(it)

`macos_item_search()` searches for Keychain items. If `return_data` is
`TRUE` then it also returns the secret data. Returning the secret data
might create a password entry dialog. If `return_data` is `TRUE` then
you need to set the `limit` match condition to a (small) finite number.

    macos_item_search(attributes = list(service = "My service"))
    #> [[1]]
    #> <oskeyring_macos_item: generic_password>
    #>  account: Gabor
    #>  creation_date: 2023-11-03 12:30:13
    #>  label: My service
    #>  modification_date: 2023-11-03 12:30:13
    #>  service: My service

`macos_item_update()` updates existing Keychain items.

    macos_item_update(
      attributes = list(service = "My service", account = "Gabor"),
      update = list(account = "Gabor Csardi")
    )
    macos_item_search(attributes = list(service = "My service"))
    #> [[1]]
    #> <oskeyring_macos_item: generic_password>
    #>  account: Gabor Csardi
    #>  creation_date: 2023-11-03 12:30:13
    #>  label: My service
    #>  modification_date: 2023-11-03 12:30:13
    #>  service: My service

`macos_item_delete()` deletes one or more Keychain items. Note that all
matching items will be deleted.

    macos_item_delete(attributes = list(service = "My service"))
    macos_item_search(attributes = list(service = "My service"))
    #> list()

### Keychain Item Attributes

- The set of supported attributes depends on the class of the item.

- oskeyring supports the following item classes currently:
  generic_password, internet_password.

- A subset of the attributes form a *primary key*. It is not possible to
  add more than one item with the same primary key. See the primary keys
  for the various classes below.

- oskeyring does not currently support all attributes that the Keychain
  Services AIP supports.

- Some attributes are read-only. If you try to set them when adding or
  updating items, they will be ignored.

- If an attribute is not included in the return value of
  `macos_item_search()` then it is not set, and its default value is in
  effect.

#### Attributes for generic passwords

- `creation_date`: \[.POSIXct(1)\]\[read-only\] The date the item was
  created.

- `modification_date`: \[.POSIXct(1)\]\[read-only\] The last time the
  item was updated.

- `description`: \[character(1)\] User-visible string describing this
  kind ofitem (for example, 'Disk image password').

- `comment`: \[character(1)\] User-editable comment for this item.

- `label`: \[character(1)\] User-visible label for this item.

- `is_invisible`: \[logical(1)\] `TRUE` if the item is invisible (that
  is, should not be displayed).

- `is_negative`: \[logical(1)\] Indicates whether there is a valid
  password associated with this keychain item. This is useful if your
  application doesn't want a password for some particular service to be
  stored in the keychain, but prefers that it always be entered by the
  user.

- `account`: \[character(1)\]\[key\] Account name.

- `service`: \[character(1)\]\[key\] The service associated with this
  item.

- `generic`: \[character(1)\] User-defined attribute.

- `synchronizable`: \[logical(1)\] Indicates whether the item in
  question is synchronized to other devices through iCloud.

#### Attributes for internet passwords

- `creation_date`: \[.POSIXct(1)\]\[read-only\] The date the item was
  created.

- `modification_date`: \[.POSIXct(1)\]\[read-only\] The last time the
  item was updated.

- `description`: \[character(1)\] User-visible string describing this
  kind ofitem (for example, 'Disk image password').

- `comment`: \[character(1)\] User-editable comment for this item.

- `label`: \[character(1)\] User-visible label for this item.

- `is_invisible`: \[logical(1)\] `TRUE` if the item is invisible (that
  is, should not be displayed).

- `is_negative`: \[logical(1)\] Indicates whether there is a valid
  password associated with this keychain item. This is useful if your
  application doesn't want a password for some particular service to be
  stored in the keychain, but prefers that it always be entered by the
  user.

- `account`: \[character(1)\]\[key\] Account name.

- `synchronizable`: \[logical(1)\] Indicates whether the item in
  question is synchronized to other devices through iCloud.

- `security_domain`: \[character(1)\]\[key\] The item's security domain.

- `server`: \[character(1)\]\[key\] Contains the server's domain name or
  IP address.

- `protocol`: \[character(1)\]\[key\] The protocol for this item.

- `authentication_type`: character\[1\]\[key\] Authentication type.

- `port`: \[integer(1)\]\[key\] Internet port number.

- `path`: \[character(1)\]\[key\] A path, typically the path component
  of the URL

## Search Parameters

osxkeychain only supports a limited set of search parameters. You can
provide these for `macos_item_search()` as the `match` argument:

- `limit`: \[numeric(1)\] This value specifies the maximum number of
  results to return or otherwise act upon. Use `Inf` to specify all
  matching items.

## Keychains

macOs supports multiple keychains. There is always a default keychain,
which is the user's login keychain, unless configured differently. There
is also a keychain search list. Keychains may belong into four
non-exclusive categories, see the `domain` argument of
`macos_keychain_list()`. A keychain is stored in an encrypted file on
the disk, see the first column of the output of `macos_keychain_list()`.

`macos_item_*()` functions have a `keychain` argument to direct or
restrict the operation to a single keychain only. These are the
defaults:

- `macos_item_add()` adds the item to the default keychain.

- `macos_item_search()` searches all keychains in the search list.

- `macos_item_update()` updates matching items on all keychains in the
  search list.

- `macos_item_delete()` deletes matching items from all keychains in the
  search list.

`macos_keychain_create()` creates a new keychain.

`macos_keychain_list()` lists all keychains on the search list.

    new <- "~/Library/Keychains/test.keychain-db"
    macos_keychain_create(new, password = "secret")
    macos_keychain_list()

    ##                                                     path is_unlocked
    ## 1 /Users/gaborcsardi/Library/Keychains/login.keychain-db        TRUE
    ## 2 /Users/gaborcsardi/Library/Keychains/shiny.keychain-db       FALSE
    ## 3  /Users/gaborcsardi/Library/Keychains/test.keychain-db        TRUE
    ## 4                     /Library/Keychains/System.keychain       FALSE
    ##   is_readable is_writeable
    ## 1        TRUE         TRUE
    ## 2        TRUE        FALSE
    ## 3        TRUE         TRUE
    ## 4        TRUE        FALSE

`macos_keychain_lock()` locks a keychain. `macos_keychain_unlock()`
unlocks a keychain. `macos_keychain_is_locked()` checks if a keychain is
locked.

    macos_keychain_lock(new)
    macos_keychain_is_locked(new)

    ## [1] TRUE

    macos_keychain_unlock(new, password = "secret")
    macos_keychain_is_locked(new)

    ## [1] FALSE

`macos_keychain_delete()` deletes a keychain: it removes it from the
search list and deletes the data from the disk. It currently refuses to
delete the user's login keychain and the system keychain. Use Keychain
Access instead if you want to delete these. (Only do this if you are
aware of the bad consequences.)

    macos_keychain_delete(new)
    macos_keychain_list()

    ##                                                     path is_unlocked
    ## 1 /Users/gaborcsardi/Library/Keychains/login.keychain-db        TRUE
    ## 2 /Users/gaborcsardi/Library/Keychains/shiny.keychain-db       FALSE
    ## 3                     /Library/Keychains/System.keychain       FALSE
    ##   is_readable is_writeable
    ## 1        TRUE         TRUE
    ## 2        TRUE        FALSE
    ## 3        TRUE        FALSE

## See also

The Keychain Services API documentation at
<https://developer.apple.com/documentation/security/keychain_services>.

## Examples

``` r
# See above
```
