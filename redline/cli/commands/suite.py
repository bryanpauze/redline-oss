"""`probes`, `profiles`, `golden`: introspect the probe suite and its eval sets."""
from __future__ import annotations


def cmd_probes(a) -> int:
    from ...core.compliance import mapping
    from ...probes import all_probes
    for p in all_probes():
        m = mapping(p.id)
        print(f"{p.id:8} [{p.severity:8}] {p.category:14} {p.title}")
        tags = m["owasp"] + m["atlas"]
        if tags:
            print(f"         {' '.join(tags)}")
    return 0


def cmd_profiles(a) -> int:
    from ...core.profiles import BUILTIN_PROFILES
    for name, prof in BUILTIN_PROFILES.items():
        print(f"  {name:16} {', '.join(prof.categories)}")
    return 0


def cmd_golden(a) -> int:
    from ...core.profiles import get_profile, run_golden
    r = run_golden(get_profile(a.profile).golden)
    ok, tot = r.get("passed", 0), r.get("total", 0)
    print(f"  golden[{a.profile}]: {ok}/{tot} passed")
    return 0 if ok == tot else 1


def register(sub) -> None:
    sub.add_parser("probes", help="list the probe suite with framework mappings").set_defaults(
        func=cmd_probes)
    sub.add_parser("profiles", help="list scan-profile bundles").set_defaults(func=cmd_profiles)

    gd = sub.add_parser("golden", help="run a profile's golden detector-regression set")
    gd.add_argument("--profile", default="general")
    gd.set_defaults(func=cmd_golden)
