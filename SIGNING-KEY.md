# Image signing key

Every InQubestigationOS release is signed with one GPG key. Use this page to
check that key before you trust a download. The release carries its own copy
of the key, and that copy proves nothing on its own: whoever can replace the
download can replace the key beside it. This page lives in the repository,
where every change is recorded in its history.

```
Fingerprint:  NOT-YET-PUBLISHED
```

`./build_iso.py package-release` writes the fingerprint above the first time it
packages a release. The maintainer then commits and pushes this file **before**
publishing the release. After that, `package-release` refuses to package a
release signed by any other key.

## Check a download against it

In the folder holding every file of the release:

```bash
gpg --import unit-signing-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS   # "Good signature", and the fingerprint above
sha256sum -c SHA256SUMS                  # every line: OK
```

Compare the line gpg labels **Primary key fingerprint**. If the key signs with
a subkey, gpg also prints a "Subkey fingerprint" that differs, and that is
normal. If the primary fingerprint differs from the one on this page, or from
the one under "Previous keys" for an older release, by even one character,
**stop**. Do not write or boot the image. The rest is in
[docs/GUIDE.md §3.3](docs/GUIDE.md#33-from-a-downloaded-release).

## Also published at

The same fingerprint should be confirmable somewhere else too, so that one
compromised account cannot change every copy. For example:

- the GitHub account's GPG keys, served at `https://github.com/<user>.gpg`
  (Settings → SSH and GPG keys → New GPG key, pasting
  `gpg --armor --export <fingerprint>`);
- keys.openpgp.org, independent of GitHub:
  `gpg --keyserver hkps://keys.openpgp.org --send-keys <fingerprint>`, then
  confirm the e-mail it sends;
- a unit intranet page, a website you control, or the phone.

List the places actually used here:

- *(none yet)*

## If the key changes

A new key is a deliberate change. Move the old fingerprint to "Previous keys"
below, with the date it stopped signing, so older releases stay verifiable.
Then put the new one on the `Fingerprint:` line by hand, say why in the commit
message, and announce it on the channels listed above.

## Previous keys

- *(none)*
