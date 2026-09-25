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

If the fingerprint gpg prints differs from the one on this page by even one
character, **stop**. Do not write or boot the image. The rest is in
[docs/GUIDE.md §3.3](docs/GUIDE.md#33-from-a-downloaded-release).

## Also published at

The same fingerprint should be confirmable somewhere outside GitHub, for
example on your unit's intranet page, a website you control, or over the phone.
List those places here:

- *(none yet)*

## If the key changes

A new key is a deliberate change. Replace the fingerprint above by hand, say
why in the commit message, and announce it on the channels listed above. The
old fingerprint stays in this file's git history.
