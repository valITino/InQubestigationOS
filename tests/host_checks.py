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


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name if ok else f"{name}\n          {detail}")


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
    check("the Debian package list does not require python3-pykickstart",
          "python3-pykickstart" not in deb or
          any("python3-pykickstart" not in cands
              for p, cands in bi.host_package_plan("debian", "docker")
              if p != "kickstart validation"),
          "it does not exist in Debian or Kali and fails the whole apt batch")
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
        print("  SKIP  live package probe: no apt-get or dnf on this host")
        return
    plan = bi.host_package_plan(fam, "docker")
    every = sorted({n for _, cands in plan for n in cands})
    avail = bi.packages_available(fam, every)
    if avail is None:
        print(f"  SKIP  live package probe on {d.described()}: "
              "the package manager could not be queried (no cache?)")
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
    for m in re.finditer(r"\./build_iso\.py ([a-z][a-z-]*)", src):
        if actions:
            check(f"the fix line `./build_iso.py {m.group(1)}` names a real action",
                  m.group(1) in actions,
                  f"build_iso.py accepts: {' '.join(sorted(actions))}")


def check_mock_is_conditional() -> None:
    """The mock configuration must never be passed unconditionally."""
    src = (ROOT / "build_iso.py").read_text()
    check("the container image build no longer forces the mock code path",
          not re.search(r'"tools/generate-container-image\.sh",\s*'
                        r'x\.c\["container_engine"\],\s*\n?\s*x\.c\["mock_config"\]',
                        src),
          "generate-container-image.sh is called with the mock config as a "
          "positional argument again — that runs `sudo mock --scrub=all`, and "
          "mock is in no Debian or Kali suite, so the build aborts under set -e")
    check("the mock config is guarded by a check that mock exists",
          'shutil.which("mock")' in src,
          "nothing tests for mock before selecting upstream's mock code path")
    # The guard has to be the thing that decides the argument, not merely
    # present somewhere else in the file.
    # The guard has to be what decides the argument, not merely present
    # somewhere else in the file: find the argv construction and the run, and
    # require the append to sit inside a which("mock") branch between them.
    m = re.search(r'gci\s*=\s*\[[^\]]*generate-container-image[^\]]*\]'
                  r'(.*?)x\.run\(\*gci', src, re.S)
    body = m.group(1) if m else ""
    code = "\n".join(l for l in body.splitlines()
                     if not l.lstrip().startswith("#"))
    check("the mock argument is appended only inside that guard",
          bool(m) and 'shutil.which("mock")' in code
          and re.search(r'if shutil\.which\("mock"\):\s*\n\s*'
                        r'gci\.append\(x\.c\["mock_config"\]\)', code)
          is not None,
          "could not find `if shutil.which(\"mock\"): gci.append(...)` between "
          "building the argv and running it")


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
    # Branches of the plan-execution loop that handle the __pykickstart__ step.
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

        # A genuinely complete host must still report nothing to do.
        bi._have_module = lambda n: True
        check("a host with everything reports no gaps", bi.host_gaps("docker") == [],
              str(bi.host_gaps("docker")))
    finally:
        bi.shutil.which, bi._have_module = real_which, real_mod


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
    check_live_availability(bi)
    check_distro_detection(bi)
    check_doctor_fix(bi)
    check_mock_is_conditional()
    check_pypi_install_is_consented()
    check_install_gate(bi)
    check_no_hardcoded_lists()
    check_pykickstart_advice()

    for f in FAILED:
        print(f"  FAIL  {f}")
    total = len(PASSED) + len(FAILED)
    print(f"\n  {len(PASSED)}/{total} build-host checks pass")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
