# Query and manipulate the Windows Credential Store

`windows_item_*` functions read, write, delete and list credentials.

## Usage

``` r
windows_item_types()

windows_item(
  credential_blob,
  target_name,
  type = "generic",
  comment = NULL,
  persist = c("local_machine", "session", "enterprise"),
  attributes = list(),
  target_alias = NULL,
  username = NULL
)

windows_item_read(target_name, type = "generic")

windows_item_write(item, preserve = FALSE)

windows_item_delete(target_name, type = "generic")

windows_item_enumerate(filter = NULL, all = FALSE)
```

## Arguments

- credential_blob:

  The secret credential, a password, certificate or key. See also
  <https://learn.microsoft.com/en-us/windows/win32/api/wincred/> This
  can be a raw vector, or a string. If it is a string, then it will be
  converted to Unicode, without the terminating zero. It can also be
  `NULL`, to be used with the `preserve = TRUE` argument of
  `windows_item_write()`.

- target_name:

  The name of the credential. The `target_name` and `type` members
  uniquely identify the credential. This member cannot be changed after
  the credential is created. Instead, the credential with the old name
  should be deleted and the credential with the new name created. This
  member cannot be longer than
  `CRED_MAX_GENERIC_TARGET_NAME_LENGTH` (32767) characters. This member
  is case-insensitive.

- type:

  The type of the credential. This member cannot be changed after the
  credential is created. See `windows_item_types()` for possible values.

- comment:

  If not `NULL`, then a string comment from the user that describes this
  credential. This member cannot be longer than
  `CRED_MAX_STRING_LENGTH` (256) characters. It is stored as a Unicode
  string.

- persist:

  Defines the persistence of this credential.

  - `"local_machine"`: The credential persists for all subsequent logon
    sessions on this same computer. It is visible to other logon
    sessions of this same user on this same computer and not visible to
    logon sessions for this user on other computers.

  - `"session"`: The credential persists for the life of the logon
    session. It will not be visible to other logon sessions of this same
    user. It will not exist after this user logs off and back on.

  - `"enterprise"`: The credential persists for all subsequent logon
    sessions on this same computer. It is visible to other logon
    sessions of this same user on this same computer and to logon
    sessions for this user on other computers.

- attributes:

  Application-defined attributes that are associated with the
  credential. This is `NULL` or a named list of raw or string vectors.
  String vectors are converted to Unicode, without the terminating zero.
  A credential can have at most 64 attributes, the names of the
  attributes cannot be longer than `CRED_MAX_STRING_LENGTH` (256)
  characters each, and the attributes themselves cannot be longer than
  `CRED_MAX_VALUE_SIZE` (256) bytes.

- target_alias:

  Alias for the `target_name` member. This member can be read and
  written. It cannot be longer than `CRED_MAX_STRING_LENGTH` (256)
  characters. It is stored in Unicode.

- username:

  `NULL` or the user name of the account used to connect to
  `target_name`.

- item:

  `oskeyring_windows_item` object to write.

- preserve:

  The credential BLOB from an existing credential is preserved with the
  same credential name and credential type. The `credential_blob` of the
  passed `oskeyring_windows_item` object must be `NULL`.

- filter:

  If not `NULL`, then a string to filter the credentials. Only
  credentials with a `target_name` matching the filter will be returned.
  The filter specifies a name prefix followed by an asterisk. For
  instance, the filter `"FRED*"` will return all credentials with a
  `target_name` beginning with the string `"FRED"`.

- all:

  Whether to use the `CRED_ENUMERATE_ALL_CREDENTIALS` flag to enumerate
  all credentials. If this is `TRUE`, then `filter` must be `NULL`. If
  this is `TRUE`, then the target name of each credential is returned in
  the `"namespace:attribute=target`" format.

## Value

`windows_item_types()` returns a character vector, the currently
supported credential types.

`windows_item()` returns an `oskeyring_windows_item` object.

`windows_item_read()` returns an `oskeyring_windows_item` object.

`windows_item_write()` returns `NULL`, invisibly.

`windows_item_delete()` returns `NULL`, invisibly.

`windows_item_enumerate()` returns a list of `oskeyring_windows_item`
items.

## Details

### `windows_item_types()`

`windows_item_types()` lists the currently supported credential types.

    windows_item_types()
    #> [1] "generic"                 "domain_password"
    #> [3] "domain_certificate"      "domain_visible_password"

### `windows_item()`

`windows_item()` creates a Windows credential, that can be then added to
the credential store.

    it <- windows_item("secret", "my-host-password")
    it
    #> <oskeyring_windows_item: generic>
    #>  target_name: my-host-password
    #>  persist: local_machine
    #>  credential_blob: <-- hidden -->

### `windows_item_write()`

Writes an item to the credential store.

    windows_item_write(it)

### `windows_item_read()`

Reads a credential with the specified type and `target_name`.

    windows_item_read("my-host-password")

### `windows_item_enumerate()`

List all credentials that match a prefix.

    windows_item_enumerate(filter = "my-*")

### `windows_item_delete()`

Delete a credential:

    windows_item_delete("my-host-password")
    windows_item_enumerate(filter = "my-*")

## See also

The API documentation at
<https://learn.microsoft.com/en-us/windows/win32/api/wincred/>

## Examples

``` r
# See above
```
