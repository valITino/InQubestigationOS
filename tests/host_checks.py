#!/usr/bin/env python3
"""
host_checks.py — the build-host support in build_iso.py must hold up on the
distributions it claims to support.

Every bug this file pins was the same bug wearing a different hat: the script
asserted a fact about a distribution instead of asking it.

  * `python3-pykickstart` was hardcoded into the Debian package list. It was
    removed from Debian in 2019 and has never existed in Kali, and `apt-get
    install -y` fails the WHOLE batch on one unknown name, so `setup-host`
    died on any fresh Debian-family host before installing anything.
  * `docker` was hardcoded into the Fedora list. It is not a Fedora binary
    package name at all — it is a virtual provide of `moby-engine`.
  * The mock configuration was passed unconditionally to upstream's
    `tools/generate-container-image.sh`, which selects a `sudo mock` code
    path. `mock` is not packaged for Debian or Kali, and that script runs
    under `set -ex`, so the container image build aborted on every
    Debian-family host — including the Debian 13 host the guide recommends.
  * `doctor --fix` built its argv without the script path, so every repair ran
    as `python3 setup-host` and died with "can't open file".
  * The install gate probed five binaries and nothing else, so a host that
    already had them installed no packages at all — and `doctor` then blocked
    on the missing python3-yaml with a fix that had just decided there was
    nothing to do.

    ./tests/host_checks.py
"""
from __future__ import annotations

import ast
import importlib.util
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAILED: list[str] = []
PASSED: list[str] = []
# Coverage this run could not exercise. Kept and reported rather than left
# implicit: a probe that quietly does not run makes "N/N pass" mean less than
# it did the run before, with nothing in the output saying so.
SKIPPED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name if ok else f"{name}\n          {detail}")


def skip(what: str, why: str) -> None:
    SKIPPED.append(f"{what} — {why}")


def load_build_iso():
    spec = importlib.util.spec_from_file_location("build_iso", ROOT / "build_iso.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
#  Packages verified NOT to exist, so that naming one is a test failure
# ---------------------------------------------------------------------------
# Checked against primary sources on 2026-09-09:
#   packages.debian.org/trixie/<pkg>, pkg.kali.org/pkg/<pkg>,
#   mdapi.fedoraproject.org/f43/pkg/<pkg>, packages.fedoraproject.org/pkgs/<pkg>
# A name here must never be the ONLY candidate for a capability. Kept offline
# and dated on purpose: this check has to work in CI without network, and a
# stale entry is visible rather than silently skipped.
KNOWN_ABSENT = {
    "debian": {
        # Removed from Debian in August 2019 (last shipped in buster), and
        # removed from kali-rolling the same year. In no current suite.
        "python3-pykickstart": "removed from Debian and Kali in 2019",
        "pykickstart": "removed from Debian and Kali in 2019",
        # Last in Debian buster as 1.3.2-2; gone from kali-rolling.
        "mock": "removed from Debian and Kali; it is a Fedora tool",
        # Docker's own repository, not Debian's or Kali's.
        "docker-ce": "third-party repository only, not Debian or Kali",
    },
    "fedora": {
        # Not a binary package name: no RPM is called "docker". `dnf install
        # docker` does succeed, because moby-engine carries Provides: docker
        # — but naming the package that actually exists says what will be
        # installed instead of relying on an indirection.
        "docker": "no RPM has this name; moby-engine merely Provides it",
        "docker-ce": "third-party repository only, not in Fedora's repos",
        # Debian's name for the bsdtar package. Fedora calls it bsdtar.
        "libarchive-tools": "Debian's name; Fedora ships bsdtar",
        "python3-yaml": "Debian's name; Fedora ships python3-pyyaml",
        "python3-venv": "Debian's split-out venv package; Fedora has no such name",
    },
}

# Capabilities a family legitimately has no package for. Each one must be
# handled somewhere else in the code, and that handling is checked below —
# an entry here is a statement about the distribution, not an excuse.
ACCEPTED_GAPS = {
    ("debian", "kickstart validation"):
        "no Debian or Kali package exists; setup-host installs it into a "
        "virtualenv instead, and doctor says so rather than recommending a "
        "command that cannot work",
}


def check_package_plan(bi) -> None:
    for fam in ("debian", "fedora"):
        for ce in ("docker", "podman"):
            plan = bi.host_package_plan(fam, ce)
            label = f"{fam}/{ce}"
            check(f"{label}: every capability names at least one package",
                  all(cands for _, cands in plan),
                  "empty candidate list for: "
                  + ", ".join(p for p, c in plan if not c))
            for purpose, cands in plan:
                absent = KNOWN_ABSENT[fam]
                real = [c for c in cands if c not in absent]
                gap = ACCEPTED_GAPS.get((fam, purpose))
                if gap:
                    check(f"{label}: '{purpose}' is a known gap, handled elsewhere",
                          not real,
                          f"it now resolves to {real} — if that package really "
                          "exists, drop the ACCEPTED_GAPS entry")
                    continue
                check(f"{label}: '{purpose}' names a package that exists",
                      bool(real),
                      "every candidate is known absent: "
                      + "; ".join(f"{c} ({absent[c]})" for c in cands if c in absent))

    # The specific regressions, named, so a failure says which bug came back.
    deb = {c for _, cands in bi.host_package_plan("debian", "docker") for c in cands}
    fed = {c for _, cands in bi.host_package_plan("fedora", "docker") for c in cands}
    # `any(... not in ...)` here was a tautology — no other capability lists
    # the package, so it was true whatever the code did. The invariant that
    # actually matters is that the name appears ONLY under the capability
    # documented as a gap, so no other install can be sunk by it.
    elsewhere = [p_ for p_, cands in bi.host_package_plan("debian", "docker")
                 if "python3-pykickstart" in cands and p_ != "kickstart validation"]
    check("python3-pykickstart is named only under the capability known to lack it",
          not elsewhere,
          "also required for: " + ", ".join(elsewhere)
          + " — it does not exist in Debian or Kali and fails the whole apt batch")
    check("no Debian capability asks for mock", "mock" not in deb,
          "mock is a Fedora tool and is in no Debian or Kali suite")
    check("the Fedora container engine is not requested as 'docker'",
          "docker" not in fed,
          "'docker' is a virtual provide of moby-engine, not a package name")
    check("the Fedora ISO reader is bsdtar, not Debian's libarchive-tools",
          "bsdtar" in fed and "libarchive-tools" not in fed,
          "Fedora ships /usr/bin/bsdtar in the bsdtar package")


def check_live_availability(bi) -> None:
    """Ask this host's real package manager whether the plan resolves.

    This is the check that would have caught both hardcoded-list bugs on the
    first CI run. It is skipped, loudly, when there is no usable package
    manager — CI runs on a Debian-family image, so it does run there.
    """
    d = bi.host_distro()
    fam = d.family
    if fam == "unknown":
        # A skipped probe is not a passing check — counting it as one would
        # make a host that cannot be probed look better tested than one that
        # can.
        skip("live package availability", "no apt-get or dnf on this host")
        return
    plan = bi.host_package_plan(fam, "docker")
    every = sorted({n for _, cands in plan for n in cands})
    avail = bi.packages_available(fam, every)
    if avail is None:
        skip("live package availability",
             f"the package manager on {d.described()} could not be queried")
        return
    for purpose, cands in plan:
        pick = next((c for c in cands if c in avail), "")
        if ACCEPTED_GAPS.get((fam, purpose)):
            continue
        check(f"{d.id or fam}: '{purpose}' resolves to an installable package",
              bool(pick), f"none of {cands} is available here")


def check_distro_detection(bi) -> None:
    """Kali, Ubuntu and Mint must be recognised as Debian-family AND named."""
    cases = [
        ("kali", {"ID": "kali", "ID_LIKE": "debian",
                  "PRETTY_NAME": "Kali GNU/Linux Rolling"}, "debian", "Kali"),
        ("debian", {"ID": "debian", "VERSION_ID": "13",
                    "PRETTY_NAME": "Debian GNU/Linux 13 (trixie)"}, "debian", "Debian"),
        ("ubuntu", {"ID": "ubuntu", "ID_LIKE": "debian",
                    "PRETTY_NAME": "Ubuntu 24.04.4 LTS"}, "debian", "Ubuntu"),
        ("linuxmint", {"ID": "linuxmint", "ID_LIKE": "ubuntu debian",
                       "PRETTY_NAME": "Linux Mint 22"}, "debian", "Mint"),
        ("fedora", {"ID": "fedora", "VERSION_ID": "43",
                    "PRETTY_NAME": "Fedora Linux 43"}, "fedora", "Fedora"),
        ("rocky", {"ID": "rocky", "ID_LIKE": "rhel centos fedora",
                   "PRETTY_NAME": "Rocky Linux 9.4"}, "fedora", "Rocky"),
    ]
    for ident, osr, want_family, want_in_name in cases:
        d = bi.host_distro(osr)
        check(f"{ident} is detected as the {want_family} family",
              d.family == want_family, f"got {d.family}")
        check(f"{ident} is named, not reduced to '{want_family}'",
              want_in_name.lower() in d.described().lower(),
              f"described() said {d.described()!r}")
        check(f"{ident} says it came from os-release",
              d.how == "/etc/os-release", d.how)
    # A Qubes app qube is a supported build host, and it can be of either
    # family. An ID this script does not recognise must therefore defer to
    # ID_LIKE rather than being claimed by one family's table.
    for like, want in (("debian", "debian"), ("fedora", "fedora")):
        d = bi.host_distro({"ID": "qubes", "ID_LIKE": like,
                            "PRETTY_NAME": f"Qubes ({like})"})
        check(f"an unrecognised ID with ID_LIKE={like} follows ID_LIKE",
              d.family == want,
              f"got {d.family}; claiming an unknown ID for one family "
              "misclassifies app qubes of the other")

    # The whole point: two derivatives must not be indistinguishable.
    kali = bi.host_distro({"ID": "kali", "ID_LIKE": "debian",
                           "PRETTY_NAME": "Kali GNU/Linux Rolling"})
    deb = bi.host_distro({"ID": "debian", "PRETTY_NAME": "Debian GNU/Linux 13"})
    check("Kali and Debian are told apart", kali.described() != deb.described(),
          "both described themselves the same way")


def check_doctor_fix(bi) -> None:
    """`doctor --fix` must run THIS script, not a bare subcommand."""
    argv = bi.fix_argv("./build_iso.py setup-host")
    check("doctor --fix runs a real file", len(argv) >= 3,
          f"argv is {argv} — the script path is missing, so it would run "
          "`python3 setup-host` and fail with \"can't open file\"")
    if len(argv) >= 3:
        check("doctor --fix names build_iso.py by an absolute path that exists",
              Path(argv[1]).is_absolute() and Path(argv[1]).is_file()
              and Path(argv[1]).name == "build_iso.py", argv[1])
        check("doctor --fix keeps the subcommand", argv[2] == "setup-host",
              " ".join(argv))
    check("doctor --fix keeps flags and drops the parenthetical",
          bi.fix_argv('./build_iso.py gen-key --uid "A B" (or --use-key auto)')[2:]
          == ["gen-key", "--uid", "A B"],
          str(bi.fix_argv('./build_iso.py gen-key --uid "A B" (or --use-key auto)')))
    check("a fix line this script does not own is left alone",
          bi.fix_argv("log out and back in")[0] == "log")

    # Every fix line that names this script must name a real subcommand.
    src = (ROOT / "build_iso.py").read_text()
    actions = set()
    for node in ast.walk(ast.parse(src)):
        if (isinstance(node, ast.Call)
                and getattr(node.func, "attr", "") == "add_argument"
                and node.args
                and getattr(node.args[0], "value", "") == "action"):
            for kw in node.keywords:
                if kw.arg == "choices":
                    actions = set(ast.literal_eval(kw.value))
    # Without this, renaming the argparse positional makes `actions` empty and
    # every check below silently disappears — the suite would still report
    # "N/N pass", with N quietly smaller.
    check("the list of subcommands could be read from build_iso.py",
          bool(actions), "no positional with choices= found; the fix-line "
          "checks below would silently not run")
    for m in re.finditer(r"\./build_iso\.py ([a-z][a-z-]*)", src):
        check(f"the fix line `./build_iso.py {m.group(1)}` names a real action",
              m.group(1) in actions,
              f"build_iso.py accepts: {' '.join(sorted(actions))}")


def check_mock_is_conditional() -> None:
    """The mock configuration must never be passed unconditionally.

    Asserted through the AST rather than by matching source text: a regex over
    the call site fails a correct reformatting and passes some incorrect
    rewrites. What matters is the shape — the argv list handed to
    generate-container-image.sh must not contain mock_config, and the only
    place mock_config joins it must be inside a branch testing for mock.
    """
    src = (ROOT / "build_iso.py").read_text()
    tree = ast.parse(src)

    def seg(n) -> str:
        return ast.get_source_segment(src, n) or ""

    # Every list literal naming the upstream script.
    argv_lists = [n for n in ast.walk(tree) if isinstance(n, ast.List)
                  and any(isinstance(e, ast.Constant)
                          and isinstance(e.value, str)
                          and "generate-container-image.sh" in e.value
                          for e in n.elts)]
    check("the container image build's argv is built as a list", bool(argv_lists),
          "could not find the call to tools/generate-container-image.sh")
    for lst in argv_lists:
        check("the mock config is not a fixed argument of the image build",
              not any("mock_config" in seg(e) for e in lst.elts),
              seg(lst) + " — passing it positionally runs `sudo mock "
              "--scrub=all`, and mock is in no Debian or Kali suite, so the "
              "build aborts under set -e")

    # Every statement that appends mock_config to that argv must sit inside a
    # test for mock being present.
    appends = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
               and getattr(n.func, "attr", "") == "append"
               and "mock_config" in seg(n)]
    check("the mock config is appended somewhere", bool(appends),
          "nothing ever adds it, so a host WITH mock silently loses the "
          "chroot path upstream prefers")
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        if not any(a in ast.walk(node) for a in appends):
            continue
        check("the mock config is appended only under a test for mock",
              'which("mock")' in seg(node.test),
              f"guarded by `{seg(node.test)}` instead of a check that mock "
              "is actually installed")
    guarded = [a for a in appends
               if any(a in ast.walk(n) for n in ast.walk(tree)
                      if isinstance(n, ast.If) and 'which("mock")' in seg(n.test))]
    check("every append of the mock config is guarded", len(guarded) == len(appends),
          f"{len(appends) - len(guarded)} unguarded")


def check_pypi_install_is_consented() -> None:
    """A download from PyPI must be in the plan the operator approves.

    setup-host prints "This will run:", asks "Proceed?", and then executes the
    plan. Installing pykickstart from PyPI anywhere other than from inside
    that plan — an unconditional call at the end of the function, say — puts a
    network install of third-party code outside the thing the operator agreed
    to. Being merely "after the prompt" is not enough: it has to be a step
    that was DISPLAYED.
    """
    src = (ROOT / "build_iso.py").read_text()
    tree = ast.parse(src)
    setup = next((n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "setup_host"), None)
    check("setup_host exists to check", setup is not None)
    if setup is None:
        return

    def calls_in(node) -> int:
        return sum(1 for n in ast.walk(node)
                   if isinstance(n, ast.Call)
                   and getattr(n.func, "id", "") == "ensure_pykickstart")

    total = calls_in(setup)
    guarded = 0
    for node in ast.walk(setup):
        if not isinstance(node, ast.If):
            continue
        test = ast.get_source_segment(src, node.test) or ""
        if "__pykickstart__" in test and "cmd" in test:
            guarded += calls_in(node)

    check("pykickstart is installed only from inside the approved plan",
          total > 0 and total == guarded,
          f"{total} call(s) to ensure_pykickstart in setup_host, {guarded} of "
          "them inside the plan step — a call outside the plan runs a PyPI "
          "download the operator never saw listed")

    body = ast.get_source_segment(src, setup) or ""
    check("the plan lists the pykickstart step so it can be seen before approving",
          '"__pykickstart__"' in body,
          "the plan has no entry for it, so the operator approves a plan that "
          "omits a PyPI download")
    check("the displayed plan names PyPI explicitly", "PyPI" in src,
          "the operator should be told where the code is downloaded from")


def check_install_gate(bi) -> None:
    """The gate must trip on more than five binaries."""
    real_which, real_mod = shutil.which, bi._have_module
    try:
        # Everything present, yaml importable, but no ISO reader anywhere.
        readers = {"bsdtar", "7z", "7za", "isoinfo", "xorriso"}
        bi.shutil.which = lambda t: None if t in readers else f"/usr/bin/{t}"
        bi._have_module = lambda n: True
        check("a missing ISO reader alone triggers the package install",
              bi.host_gaps("docker") != [],
              "host_gaps() saw nothing to do, so setup-host would install "
              "nothing and doctor would keep blocking on the missing reader")

        # Everything present including a reader, but no PyYAML.
        bi.shutil.which = lambda t: f"/usr/bin/{t}"
        bi._have_module = lambda n: n != "yaml"
        gaps = bi.host_gaps("docker")
        check("a missing python3-yaml alone triggers the package install",
              gaps != [],
              "host_gaps() saw nothing to do — this is the deadlock: doctor "
              "blocks on python3-yaml with the fix ./build_iso.py setup-host, "
              "and setup-host decides there is nothing to install")
        check("the PyYAML gap says what is missing",
              any("yaml" in g.lower() for g in gaps), str(gaps))
        check("the PyYAML gap is not named by one distribution's package name",
              not any(g in ("python3-yaml", "python3-pyyaml") for g in gaps),
              f"{gaps} — this message is printed on both families")


        # A host with everything EXCEPT a kickstart validator must still
        # trigger the package install. Probing only Debian's half of this —
        # ensurepip, from python3-venv — left the worse case unfixed: a Fedora
        # host, where the validator IS packaged, skipped the install step and
        # went to PyPI for a module dnf already had.
        bi._have_module = lambda n: True
        check("a missing kickstart validator alone triggers the package install",
              bi.host_gaps("docker", True) != [],
              "setup-host would install nothing and go straight to a PyPI "
              "download, even on a distribution that packages the validator")

        # A genuinely complete host must still report nothing to do.
        check("a host with everything reports no gaps",
              bi.host_gaps("docker", False) == [],
              str(bi.host_gaps("docker", False)))
    finally:
        bi.shutil.which, bi._have_module = real_which, real_mod


def check_probe_itself(bi) -> None:
    """The availability probe needs a control at each end, or it proves nothing.

    Every other check here trusts packages_available(). If it silently
    returned the empty set — a parser that stopped matching, a locale change —
    the plan checks would still pass while setup-host installed nothing.
    """
    d = bi.host_distro()
    if d.family == "unknown":
        skip("probe controls", "no apt-get or dnf on this host")
        return
    # A name no distribution has, and one every one of them does.
    certainly_absent = "zzzz-not-a-real-package-name-9f3c"
    certainly_present = "python3"
    got = bi.packages_available(d.family, [certainly_present, certainly_absent])
    if got is None:
        skip("probe controls", "the package manager could not be queried")
        return
    check("the probe finds a package that certainly exists",
          certainly_present in got,
          f"packages_available said {certainly_present} is unavailable — the "
          "probe is broken and every plan check above is meaningless")
    check("the probe rejects a package that certainly does not exist",
          certainly_absent not in got,
          "the probe reports made-up names as available, so it cannot catch "
          "a package list naming something that does not exist")
    check("the probe returns None rather than an empty set when nothing matches",
          bi.packages_available(d.family, [certainly_absent]) is None,
          "an all-miss result must read as 'could not tell' so the caller "
          "still tries, rather than as 'install nothing'")
    check("the probe returns an empty set for an empty request",
          bi.packages_available(d.family, []) == set())

    # An ACCEPTED_GAPS entry that has quietly become installable is good news,
    # but the ledger has to be updated for it — the dated comment cannot
    # notice on its own.
    for (fam, purpose), _why in ACCEPTED_GAPS.items():
        if fam != d.family:
            continue
        cands = next((c for p_, c in bi.host_package_plan(fam, "docker")
                      if p_ == purpose), [])
        avail = bi.packages_available(fam, cands) if cands else None
        check(f"'{purpose}' is still genuinely unavailable on {d.id or fam}",
              not avail,
              f"{sorted(avail or [])} is installable here now — drop the "
              "ACCEPTED_GAPS entry and the KNOWN_ABSENT rows, and let "
              "setup-host install the package instead of building a virtualenv")


def check_module_probe(bi) -> None:
    """_have_module is monkeypatched by the gate test, so test the real one."""
    check("_have_module finds a module that exists", bi._have_module("json"))
    check("_have_module reports a module that does not exist as absent",
          not bi._have_module("zzzz_not_a_module_9f3c"))
    # A half-installed or version-mismatched module can raise anything at all
    # at import time. A readiness probe must answer "no", not take the caller
    # down with it. A real module on sys.path that raises is the only way to
    # test this that does not depend on import-system internals.
    import sys as _sys
    import tempfile as _tempfile
    with _tempfile.TemporaryDirectory() as tmp:
        name = "zzzz_broken_module_9f3c"
        Path(tmp, name + ".py").write_text(
            'raise RuntimeError("this module is deliberately broken")\n')
        _sys.path.insert(0, tmp)
        try:
            # The failure mode under test is an exception escaping, so catch
            # it here and report it as a failed check rather than letting it
            # abort the rest of the suite.
            try:
                survived = bi._have_module(name) is False
                detail = ""
            except Exception as e:
                survived, detail = False, f"{type(e).__name__}: {e}"
            check("_have_module survives a module that raises on import",
                  survived,
                  detail or "it returned True for a module that cannot be "
                  "imported")
        finally:
            _sys.path.remove(tmp)
            _sys.modules.pop(name, None)


def check_resolution(bi) -> None:
    """resolve_host_packages decides what actually gets installed."""
    real = bi.packages_available
    try:
        # Pretend the host has everything except the known gap.
        bi.packages_available = lambda fam, names: {
            n for n in names if n != "python3-pykickstart"}
        install, missing, probed = bi.resolve_host_packages(_Quiet(), "debian", "docker")
        check("resolution reports that it probed", probed is True)
        check("resolution picks the first available candidate per capability",
              "docker.io" in install and "docker-ce" not in install,
              str(install))
        check("resolution names the capability it has no package for",
              len(missing) == 1 and "kickstart" in missing[0].lower(), str(missing))
        check("resolution never proposes a package the probe rejected",
              "python3-pykickstart" not in install, str(install))

        # Pretend the probe itself did not work.
        bi.packages_available = lambda fam, names: None
        install2, missing2, probed2 = bi.resolve_host_packages(_Quiet(), "debian", "docker")
        check("an unusable probe is reported as not-probed", probed2 is False,
              "the caller would batch-install a list it has no reason to trust")
        check("an unusable probe still proposes every capability",
              len(install2) == len(bi.host_package_plan("debian", "docker")),
              str(install2))
        check("an unusable probe claims nothing is unavailable", missing2 == [],
              "it cannot know that, and saying so would skip real packages")
    finally:
        bi.packages_available = real


class _Quiet:
    """Just enough Ctx for the functions under test to report through."""
    def info(self, *a, **k): pass
    def ok(self, *a, **k): pass
    def warn(self, *a, **k): pass


def check_os_release_reading(bi) -> None:
    """The real file reader and the $PATH fallback, not just injected dicts."""
    osr = bi.host_os_release()
    check("os-release is readable on this host and names an ID",
          bool(osr.get("ID")),
          f"parsed {sorted(osr)[:8]} — every check that injects a dict is "
          "meaningless if the real reader cannot produce one")
    check("os-release values are unquoted",
          not any(v.startswith('"') or v.endswith('"') for v in osr.values()),
          str({k: v for k, v in osr.items() if '"' in v}))
    # An empty dict forces the fallback that used to be the ONLY detection.
    d = bi.host_distro({})
    check("with no os-release, detection falls back to the package manager",
          d.how.endswith("on $PATH") or d.how == "no package manager found",
          d.how)
    check("the fallback agrees with what is actually installed",
          (d.family == "debian") == bool(bi.shutil.which("apt-get"))
          or d.family == "fedora",
          f"{d.family} but apt-get is "
          f"{'present' if bi.shutil.which('apt-get') else 'absent'}")


def check_family_neutral_messages() -> None:
    """Operator-facing text must not name one family's package to the other."""
    src = (ROOT / "build_iso.py").read_text()
    tree = ast.parse(src)
    docstrings = set()
    for node in ast.walk(tree):
        b = getattr(node, "body", None)
        if isinstance(b, list) and b and isinstance(b[0], ast.Expr) \
                and isinstance(b[0].value, ast.Constant) \
                and isinstance(b[0].value.value, str):
            docstrings.add(id(b[0].value))
    bare = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Constant) and isinstance(n.value, str)):
            continue
        if id(n) in docstrings or "python3-yaml" not in n.value:
            continue
        # Naming it alongside the other family's package is correct, and so is
        # the bare name inside the package plan, where it IS the Debian answer.
        if "python3-pyyaml" in n.value or n.value.strip() == "python3-yaml":
            continue
        bare.append(n.lineno)
    check("no operator message names python3-yaml without its Fedora counterpart",
          not bare,
          "lines " + ", ".join(map(str, bare))
          + " tell a Fedora operator to install a Debian package")


def note_unprobed_family(bi) -> None:
    """Say which family's package names were only checked against the ledger.

    One process runs on one distribution, so the other family's names are
    verified against KNOWN_ABSENT in that process. CI runs this suite once on
    each family, but a standalone run must still state its own coverage rather
    than silently taking credit for a different job.
    """
    fam = bi.host_distro().family
    other = {"debian": "fedora", "fedora": "debian"}.get(fam)
    if other:
        skip(f"live {other} package names",
             f"this host is {fam}-family; {other} names are checked only "
             "against the dated KNOWN_ABSENT ledger")


def check_ci_covers_both_families() -> None:
    """CI must live-query both supported package-manager families."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

    def job_body(name: str) -> str | None:
        match = re.search(
            rf"(?ms)^  {re.escape(name)}:\n"
            rf"(?P<body>.*?)(?=^  [A-Za-z_][A-Za-z0-9_-]*:\n|\Z)",
            workflow,
        )
        return match.group("body") if match else None

    ubuntu_job = job_body("harness")
    check("CI runs the Debian-family live package probe on Ubuntu",
          ubuntu_job is not None
          and "runs-on: ubuntu-latest" in ubuntu_job
          and "run: ./tests/host_checks.py" in ubuntu_job,
          "the normal Ubuntu host check is missing")
    if ubuntu_job:
        universe = ubuntu_job.find("add-apt-repository --yes universe")
        apt_update = ubuntu_job.find("sudo apt-get update")
        harness = ubuntu_job.find("run: ./tests/run_tests.py")
        check("CI enables Ubuntu universe before probing build-host packages",
              0 <= universe < apt_update,
              "docker.io and libarchive-tools are in universe; apt-get update "
              "cannot expose a repository that is disabled")
        check("CI refreshes APT metadata before either live package probe",
              0 <= apt_update < harness,
              "stale hosted-runner indexes make host_checks fail both inside "
              "run_tests.py and in its standalone CI step")
    fedora_job = job_body("fedora-host")
    check("CI has a dedicated Fedora host-check job", fedora_job is not None,
          "add a fedora-host job so DNF package availability is tested live")
    if fedora_job:
        check("the Fedora host-check job runs in a Fedora container",
              re.search(r"(?m)^\s+image:\s*fedora:\d+\s*$", fedora_job) is not None,
              "the fedora-host job has no versioned Fedora container")
        check("the Fedora job runs the complete host-check suite",
              "python3 ./tests/host_checks.py" in fedora_job,
              "Fedora starts, but host_checks.py is not executed there")


def check_no_hardcoded_lists() -> None:
    """The two flat cross-distro lists must not come back."""
    src = (ROOT / "build_iso.py").read_text()
    for name in ("DEB_PACKAGES", "RPM_PACKAGES"):
        check(f"{name} is gone", f"{name} =" not in src,
              "a flat per-distribution package list is what made a name that "
              "does not exist on one distribution fail the install on all of "
              "them — use host_package_plan()'s candidates instead")


def check_pykickstart_advice() -> None:
    """doctor must not tell a Debian host to run a command that cannot help."""
    src = (ROOT / "build_iso.py").read_text()
    check("setup-host installs pykickstart when no package provides it",
          "def ensure_pykickstart" in src and "ensure_pykickstart(x)" in src,
          "nothing installs pykickstart on a distribution that does not "
          "package it")
    check("the kickstart validator uses whichever interpreter has pykickstart",
          "def kickstart_python" in src
          and re.search(r"py,\s*_\s*=\s*kickstart_python\(x\)", src) is not None,
          "validate_kickstart still hardcodes sys.executable, so the "
          "virtualenv setup-host builds would never be used")
    # Naming the flag in a comment or docstring that explains why it is NOT
    # used must stay legal; passing it to pip must not. Only string literals
    # that are real code count, so the AST decides rather than a grep.
    tree = ast.parse(src)
    docstrings = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            docstrings.add(id(body[0].value))
    passed_to_pip = [n for n in ast.walk(tree)
                     if isinstance(n, ast.Constant)
                     and isinstance(n.value, str)
                     and "--break-system-packages" in n.value
                     and id(n) not in docstrings]
    check("the virtualenv is not created by overriding PEP 668",
          not passed_to_pip,
          "installing into the system interpreter over the distribution's "
          "objection is not this script's call to make (line "
          + ", ".join(str(n.lineno) for n in passed_to_pip) + ")")


def main() -> int:
    bi = load_build_iso()
    check_package_plan(bi)
    check_probe_itself(bi)
    check_module_probe(bi)
    check_resolution(bi)
    check_os_release_reading(bi)
    check_live_availability(bi)
    check_distro_detection(bi)
    check_doctor_fix(bi)
    check_mock_is_conditional()
    check_pypi_install_is_consented()
    check_install_gate(bi)
    check_family_neutral_messages()
    note_unprobed_family(bi)
    check_ci_covers_both_families()
    check_no_hardcoded_lists()
    check_pykickstart_advice()

    for f in FAILED:
        print(f"  FAIL  {f}")
    for sk in SKIPPED:
        print(f"  SKIP  {sk}")
    total = len(PASSED) + len(FAILED)
    tail = f", {len(SKIPPED)} skipped" if SKIPPED else ""
    print(f"\n  {len(PASSED)}/{total} build-host checks pass{tail}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
