#!/usr/bin/env python3
"""
static_checks.py — assertions over the files the provisioner generated.

docs/REVIEW.md claims a set of static checks over every generated configuration
file. This is that set, committed so the claim is reproducible and so a
regression is caught by CI rather than by an investigator whose DNS quietly
stopped being enforced.

Input is a capture tree produced by tests/qubes_stub.py:
    <capture>/<qube>/<path with leading slash stripped>

    ./static_checks.py <capture-dir>
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

FAILED: list[str] = []
PASSED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name if ok else f"{name}: {detail}")


def read(cap: Path, qube: str, path: str) -> str | None:
    p = cap / qube / path.lstrip("/")
    return p.read_text() if p.is_file() else None


def mode(cap: Path, qube: str, path: str) -> str | None:
    p = cap / qube / (path.lstrip("/") + ".mode")
    return p.read_text().strip() if p.is_file() else None


# ---------------------------------------------------------------------------
#  nftables
# ---------------------------------------------------------------------------
VALID_HOOKS = {"prerouting", "input", "forward", "output", "postrouting"}
VALID_TYPES = {"filter", "nat", "route"}


def check_nft_text(label: str, text: str) -> None:
    exec_lines = [line for line in text.splitlines()
                  if line.strip() and not line.strip().startswith("#")]
    body = "\n".join(exec_lines)

    check(f"{label}: braces balance",
          body.count("{") == body.count("}"),
          f"{body.count('{')} open vs {body.count('}')} close")

    check(f"{label}: no reference to the non-existent custom-prerouting chain",
          "custom-prerouting" not in body)

    for m in re.finditer(r"type\s+(\w+)\s+hook\s+(\w+)", body):
        t, h = m.group(1), m.group(2)
        check(f"{label}: chain type '{t}' is valid", t in VALID_TYPES, t)
        check(f"{label}: hook '{h}' is valid", h in VALID_HOOKS, h)

    # 'redirect' is only legal in a nat prerouting context.
    for line in exec_lines:
        if "redirect to" not in line:
            continue
        chain = ""
        m = re.search(r"(custom-dnat-\w+|dnat-dns)", line)
        if m:
            chain = m.group(1)
        ctx = body
        check(f"{label}: 'redirect to' sits in a nat/prerouting context",
              ("type nat hook prerouting" in ctx) or chain.startswith("custom-dnat")
              or chain == "dnat-dns",
              line.strip())

    # nft set literals need spaces inside the braces.
    for line in exec_lines:
        for m in re.finditer(r"\{[^}]*\}", line):
            s = m.group(0)
            if "," not in s:
                continue
            check(f"{label}: set literal '{s}' is spaced for nft",
                  s.startswith("{ ") and s.endswith(" }"), line.strip())

    # A line-continuation backslash must never be the last char of a comment.
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("#") and line.rstrip().endswith("\\"):
            check(f"{label}: comment on line {i} does not swallow the next line",
                  False, line)


def checks_firewall(cap: Path, qube: str) -> None:
    dns = read(cap, qube, "/rw/config/qubes-firewall.d/10-golden-dns")
    check(f"{qube}: DNS script written to qubes-firewall.d", dns is not None)
    if dns:
        check_nft_text(f"{qube}/10-golden-dns", dns)
        check(f"{qube}: DNS script is an nft script",
              dns.startswith("#!/usr/sbin/nft -f"), dns.splitlines()[0])
        check(f"{qube}: dnat-dns uses the add-then-delete idiom",
              "add chain ip qubes dnat-dns" in dns and "delete chain ip qubes dnat-dns" in dns)
        check(f"{qube}: dnat-dns keeps the dstnat priority",
              "priority dstnat" in dns)
        check(f"{qube}: DNS script is executable", mode(cap, qube, "/rw/config/qubes-firewall.d/10-golden-dns") in ("0755", "755"))
        check(f"{qube}: no DNS rule targets the Tor gateway",
              "sys-whonix" not in [w for w in re.findall(r"^\s*(?!#)(.*)$", dns, re.M) if "sys-whonix" in w])

    us = read(cap, qube, "/rw/config/qubes-firewall-user-script")
    check(f"{qube}: firewall user script written", us is not None)
    if us:
        check_nft_text(f"{qube}/user-script", us)
        check(f"{qube}: downstream DNS accepted on custom-input",
              "custom-input" in us and "dport 53" in us)
        check(f"{qube}: raw upstream port 53 dropped on custom-forward",
              re.search(r"custom-forward.*dport 53.*drop", us) is not None)
        check(f"{qube}: inter-qube traffic dropped (10.137 -> 10.137)",
              "10.137.0.0/16 ip daddr 10.137.0.0/16" in us)
        check(f"{qube}: user script is executable",
              mode(cap, qube, "/rw/config/qubes-firewall-user-script") in ("0755", "755"))


def checks_proxy(cap: Path, qube: str) -> None:
    us = read(cap, qube, "/rw/config/qubes-firewall-user-script")
    check(f"{qube}: firewall user script written", us is not None)
    if us:
        check_nft_text(f"{qube}/user-script", us)
        check(f"{qube}: creates its own nat chain rather than using custom-prerouting",
              "add chain ip qubes custom-dnat-squid" in us)
        check(f"{qube}: nat chain is prerouting at filter+1",
              re.search(r"type nat hook prerouting priority filter \+ 1", us) is not None)
        check(f"{qube}: port 80 redirected to Squid", "tcp dport 80  redirect to :3128" in us or "tcp dport 80 redirect to :3128" in us)
        check(f"{qube}: port 443 redirected to Squid", "redirect to :3129" in us)
        check(f"{qube}: redirected packets accepted on custom-input",
              re.search(r"custom-input.*3128.*3129.*accept", us) is not None)

    sq = read(cap, qube, "/rw/config/squid-golden.conf")
    check(f"{qube}: squid config written", sq is not None)
    if sq:
        check(f"{qube}: squid intercepts both ports",
              "http_port  3128 intercept" in sq and "https_port 3129 intercept" in sq)
        check(f"{qube}: TLS is peeked then spliced, never decrypted",
              "ssl_bump peek step1" in sq and "ssl_bump splice all" in sq)
        check(f"{qube}: no bump/terminate directive (that would decrypt)",
              not re.search(r"^\s*ssl_bump\s+(bump|terminate)", sq, re.M))
        check(f"{qube}: host certificate generation is off",
              "generate-host-certificates=off" in sq)
        check(f"{qube}: access log carries the originating qube address (%>a)",
              "%>a" in sq)
        check(f"{qube}: access log carries the TLS SNI",
              "%ssl::>sni" in sq)
        check(f"{qube}: only qube subnets are allowed",
              "acl localqubes src 10.137.0.0/16 10.138.0.0/16" in sq
              and "http_access deny all" in sq)

    ub = read(cap, qube, "/rw/config/unbound-quad9.conf")
    if ub is not None:
        check_unbound(f"{qube}/unbound", ub)


def check_unbound(label: str, ub: str) -> None:
    check(f"{label}: forwards over TLS", "forward-tls-upstream: yes" in ub)
    check(f"{label}: no cleartext fallback", "forward-first: no" in ub)
    check(f"{label}: upstreams are pinned to port 853 with a TLS name",
          all("@853#" in line for line in ub.splitlines()
              if "forward-addr" in line))
    check(f"{label}: a CA bundle is configured for upstream validation",
          "tls-cert-bundle:" in ub)
    check(f"{label}: not an open resolver", "access-control: 0.0.0.0/0 refuse" in ub)
    check(f"{label}: qube subnets are allowed",
          "access-control: 10.137.0.0/16 allow" in ub)


def checks_ids(cap: Path, qube: str, fail_closed: bool = True) -> None:
    us = read(cap, qube, "/rw/config/qubes-firewall-user-script")
    check(f"{qube}: firewall user script written", us is not None)
    if us:
        check_nft_text(f"{qube}/user-script", us)
        check(f"{qube}: uses 'queue num' (nft syntax), not 'queue to'",
              "queue num" in us and "queue to" not in us)
        exec_lines = [line for line in us.splitlines()
                      if line.strip() and not line.strip().startswith("#")]
        has_bypass = any("bypass" in line for line in exec_lines)
        check(f"{qube}: fail-closed IPS has no 'bypass' in any executable line",
              has_bypass is not fail_closed,
              "bypass present in an executable line" if fail_closed else "bypass missing")

    # The unit belongs in the TEMPLATE: sys-ids is an AppVM, so /etc outside a
    # bind-dirs entry is discarded at shutdown and a unit written into the qube
    # is gone by the first reboot — taking the fail-closed chain's only listener
    # with it.
    svc = None
    for tpl in ("tpl-ids", "investigator-ids"):
        svc = read(cap, tpl, "/etc/systemd/system/suricata-nfqueue.service")
        if svc:
            break
    check(f"{qube}: suricata unit installed into the template, not the AppVM",
          svc is not None,
          "not found in tpl-ids — it would not survive a reboot")
    check(f"{qube}: no suricata unit written into the ephemeral AppVM root",
          read(cap, qube, "/etc/systemd/system/suricata-nfqueue.service") is None)
    if svc:
        check_systemd_unit(f"{qube}/suricata-nfqueue.service", svc,
                           want_install=True)
        check(f"{qube}: suricata binds the same queue number as the nft rule",
              "-q 0" in svc)


def check_systemd_unit(label: str, text: str, want_install: bool) -> None:
    check(f"{label}: has a [Unit] section", "[Unit]" in text)
    check(f"{label}: has a Description", re.search(r"^Description=\S", text, re.M) is not None)
    check(f"{label}: has a [Service] or [Timer] section",
          "[Service]" in text or "[Timer]" in text)
    if "[Service]" in text:
        check(f"{label}: has an ExecStart", re.search(r"^ExecStart=\S", text, re.M) is not None)
    if want_install:
        check(f"{label}: has an [Install] section so 'enable' works", "[Install]" in text)
        check(f"{label}: [Install] names a target",
              re.search(r"^(WantedBy|RequiredBy)=\S", text, re.M) is not None)


def checks_placeholders(cap: Path) -> None:
    """No generated file may ship an unsubstituted template placeholder."""
    bad = []
    for p in cap.rglob("*"):
        if not p.is_file() or p.name.endswith(".mode"):
            continue
        t = p.read_text(errors="replace")
        for pat in (r"\{\w+\[", r"MANAGER_IP", r"@[A-Z_]+@", r"\bTODO\b", r"CHANGEME"):
            if re.search(pat, t):
                # MANAGER_IP only ever appears as the sed *search* term.
                if pat == r"MANAGER_IP" and "s|<address>MANAGER_IP</address>|" in t:
                    continue
                bad.append(f"{p.relative_to(cap)} matches {pat}")
    check("no generated file carries an unsubstituted placeholder", not bad, "; ".join(bad))


def checks_modes(cap: Path) -> None:
    for p in cap.rglob("*.mode"):
        rel = str(p.relative_to(cap))[:-5]
        m = p.read_text().strip()
        if rel.endswith("authd.pass") or "golden-authd" in rel:
            check(f"{rel} is not world readable", m in ("0600", "600", "0640", "640"), m)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    cap = Path(argv[1])
    if not cap.is_dir():
        print(f"no capture directory: {cap}", file=sys.stderr)
        return 2

    # Only the chain qubes carry these files. Matching on a substring also hit
    # the TEMPLATES (tpl-proxy, tpl-ids), which are not configured here and
    # legitimately have none of them.
    qubes = {p.name for p in cap.iterdir() if p.is_dir()}
    for q, fn in (("sys-firewall", checks_firewall),
                  ("sys-proxy", checks_proxy),
                  ("sys-ids", checks_ids)):
        if q in qubes:
            fn(cap, q)
        else:
            check(f"{q} was configured", False, "no captured files for it at all")
    checks_placeholders(cap)
    checks_modes(cap)

    for f in FAILED:
        print(f"  FAIL  {f}")
    total = len(PASSED) + len(FAILED)
    print(f"\n  {len(PASSED)}/{total} static checks pass")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
