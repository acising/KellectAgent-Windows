#!/usr/bin/env python3
"""
Lint the Kellect ETW schema profiles and cross-check them against a
--schema-probe report.

Kernel (classic) ETW events have no manifest, so Kellect decodes the raw
UserData frame with the layouts in config/eventStruct_*.xml. A wrong layout is
silent data corruption, and the only way to notice it is to compare the declared
sizes with the frame lengths an actual machine produces.

Typical workflow for a new Windows build (e.g. Win11):

    # 1. on the target machine, capture the real frame lengths
    kellect.exe -e all -c --schema-probe schema-win11.json
    # (stop it after a minute)

    # 2. check the current profile against the measurement
    python tools/schema_lint.py --probe schema-win11.json

    # 3. patch config/eventStruct_win11.xml, re-run this script until clean,
    #    then rebuild.

Checks performed without a probe report:
  * XML well-formedness and per-event structure
  * unknown attribute type codes
  * duplicate (providerId, opCode) pairs
  * attribute names missing from BaseEvent::propertyNameVector
    (source/initialization/initializer.cpp) - a name without an index breaks
    the typed getProperty()/setProperty() calls at runtime
  * layout differences between profiles (win7 / win10 / win11)
"""

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

TYPE_FIXED = {1: 1, 2: 2, 4: 4, 8: 8, 13: 8}
TYPE_ANSI = 11
TYPE_UTF16 = 10
TYPE_SID = 12
TYPE_NAMES = {
    1: "byte", 2: "ushort", 4: "ulong", 8: "ulong64", 13: "ulonglong",
    10: "utf16str", 11: "ansistr", 12: "sid",
}

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(REPO_ROOT, "source", "config")
INITIALIZER_CPP = os.path.join(REPO_ROOT, "source", "initialization", "initializer.cpp")


def load_profile(path):
    """Return (name, min_build, max_build, [event dicts])."""
    with open(path, "rb") as f:
        data = f.read()

    # The shipped files declare encoding="gb2312"; ElementTree refuses
    # multi-byte encodings. The content is ASCII apart from comments, so decode
    # explicitly and re-encode as UTF-8 before parsing.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("gb2312", errors="replace")
    text = re.sub(r'encoding="[^"]+"', 'encoding="utf-8"', text, count=1)
    root = ET.fromstring(text.encode("utf-8"))
    if root.tag != "Events":
        raise SystemExit("%s: root element is <%s>, expected <Events>" % (path, root.tag))

    events = []
    for ev in root.findall("Event"):
        try:
            provider = int((ev.findtext("ProviderID") or "").strip())
            opcode = int((ev.findtext("OpCode") or "").strip())
        except ValueError:
            raise SystemExit("%s: event with non-numeric ProviderID/OpCode" % path)
        name = (ev.findtext("EventName") or "").strip()
        attrs = []
        for a in ev.findall("Attributes/Attribute"):
            typ = int(a.get("type", "-1"))
            optional = a.get("optional", "0") in ("1", "true", "yes")
            attrs.append(((a.text or "").strip(), typ, optional))
        events.append({
            "provider": provider,
            "opcode": opcode,
            "name": name,
            "attrs": attrs,
        })
    return {
        "name": root.get("Name") or os.path.basename(path),
        "min_build": int(root.get("MinBuild", "0")),
        "max_build": int(root.get("MaxBuild", "0")),
        "events": events,
        "path": path,
    }


def layout_size(attrs):
    """Bytes consumed up to the first variable-width field, and whether the
    layout has any variable-width field at all."""
    prefix = 0
    for name, typ, optional in attrs:
        if typ in TYPE_FIXED:
            prefix += TYPE_FIXED[typ]
            continue
        if typ == TYPE_UTF16:
            return prefix, True, name
        if typ == TYPE_ANSI:
            return prefix, True, name
        if typ == TYPE_SID:
            # legacy contract: two pointer-sized fields skipped before the SID
            return prefix + 16, True, name
        return prefix, True, name  # unknown type: treat as variable
    return prefix, False, None


def property_name_vector():
    with open(INITIALIZER_CPP, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    m = re.search(r'std::string tempString = "([^"]+)"', text)
    if not m:
        return None
    return [p for p in m.group(1).split(",") if p]


def check_profile(profile, known_names, errors, warnings):
    label = profile["name"]
    seen = {}
    for ev in profile["events"]:
        key = (ev["provider"], ev["opcode"])
        if key in seen:
            errors.append("%s: duplicate event (%d, %d): %s vs %s"
                          % (label, key[0], key[1], seen[key], ev["name"]))
        seen[key] = ev["name"]

        if not ev["name"]:
            errors.append("%s: event (%d, %d) has no EventName" % (label, key[0], key[1]))

        for name, typ, optional in ev["attrs"]:
            if typ not in TYPE_NAMES:
                errors.append("%s/%s: unknown type %d for '%s'" % (label, ev["name"], typ, name))
            if not name:
                errors.append("%s/%s: empty attribute name" % (label, ev["name"]))
            elif known_names is not None and name not in known_names:
                warnings.append(
                    "%s/%s: attribute '%s' is not in BaseEvent::propertyNameVector; "
                    "typed getProperty()/setProperty() will not find it" % (label, ev["name"], name))


def compare_profiles(profiles):
    """Report layout differences between the profiles (win7 vs win10 etc.)."""
    lines = []
    base = profiles[0]
    base_map = {(e["provider"], e["opcode"]): e for e in base["events"]}

    for other in profiles[1:]:
        lines.append("")
        lines.append("### %s (%d..%d) vs %s (%d..%d)"
                     % (base["name"], base["min_build"], base["max_build"],
                        other["name"], other["min_build"], other["max_build"]))
        other_map = {(e["provider"], e["opcode"]): e for e in other["events"]}
        changed = 0
        for key in sorted(set(base_map) | set(other_map)):
            a = base_map.get(key)
            b = other_map.get(key)
            if a is None:
                lines.append("  + %-28s added in %s" % (b["name"], other["name"]))
                changed += 1
                continue
            if b is None:
                lines.append("  - %-28s missing in %s" % (a["name"], other["name"]))
                changed += 1
                continue
            if a["attrs"] == b["attrs"]:
                continue
            changed += 1
            lines.append("  ~ %s" % a["name"])
            sa = ["%s:%s" % (n, TYPE_NAMES.get(t, t)) for n, t, _ in a["attrs"]]
            sb = ["%s:%s" % (n, TYPE_NAMES.get(t, t)) for n, t, _ in b["attrs"]]
            only_a = [x for x in sa if x not in sb]
            only_b = [x for x in sb if x not in sa]
            if only_a:
                lines.append("      only in %s: %s" % (base["name"], ", ".join(only_a)))
            if only_b:
                lines.append("      only in %s: %s" % (other["name"], ", ".join(only_b)))
            if not only_a and not only_b:
                lines.append("      field order changed")
        if changed == 0:
            lines.append("  (identical layouts)")
    return lines


def cross_check(profile, probe_path, errors, notes):
    with open(probe_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    by_key = {(e["provider"], e["opcode"]): e for e in profile["events"]}
    lines = []
    lines.append("")
    lines.append("### probe cross-check: %s vs %s" % (profile["name"], probe_path))
    lines.append("  %-30s %-10s %8s %8s  %s" % ("event", "kind", "layout", "observed", "status"))

    checked = 0
    problems = 0
    for item in sorted(report.get("events", []), key=lambda x: (x["providerId"], x["opCode"])):
        key = (int(item["providerId"]), int(item["opCode"]))
        ev = by_key.get(key)
        name = ev["name"] if ev else item.get("eventName", "?")
        prefix, variable, _ = layout_size(ev["attrs"]) if ev else (0, True, None)

        lengths = [int(k) for k in item.get("lengths", {}).keys()]
        if not lengths:
            continue
        observed_min, observed_max = min(lengths), max(lengths)
        checked += 1

        if ev is None:
            status = "NOT IN PROFILE"
            problems += 1
        elif not variable:
            if observed_min == prefix == observed_max:
                status = "exact"
            elif observed_min >= prefix and observed_max <= prefix:
                status = "exact"
            elif observed_min > prefix:
                status = "extended +%d..+%d (unnamed tail)" % (observed_min - prefix, observed_max - prefix)
                notes.append("%s: frame is %d bytes longer than the profile - append the "
                             "missing fields to the XML" % (name, observed_min - prefix))
            else:
                status = "OVERFLOW: layout %d > frame %d..%d" % (prefix, observed_min, observed_max)
                errors.append("%s: declared layout needs %d bytes but frames are %d..%d; "
                              "the field list is wrong for this build"
                              % (name, prefix, observed_min, observed_max))
                problems += 1
        else:
            if observed_min < prefix:
                status = "OVERFLOW before variable field (%d < %d)" % (observed_min, prefix)
                errors.append("%s: frames are %d bytes but the fixed prefix is %d"
                              % (name, observed_min, prefix))
                problems += 1
            else:
                status = "variable (fixed prefix %d)" % prefix

        lines.append("  %-30s %-10s %8d %8d  %s"
                     % (name, "fixed" if not variable else "variable",
                        prefix, observed_min, status))

    lines.append("  checked=%d problems=%d" % (checked, problems))
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config-dir", default=CONFIG_DIR)
    ap.add_argument("--probe", help="JSON report produced by --schema-probe")
    ap.add_argument("--profile", help="only cross-check this profile name (e.g. win11)")
    ap.add_argument("--build", type=int,
                    help="simulate schema selection for this Windows build number")
    ap.add_argument("--sizes", action="store_true",
                    help="print a markdown table of per-event layout sizes")
    ap.add_argument("--quiet", action="store_true", help="only print problems")
    args = ap.parse_args()

    paths = sorted(
        os.path.join(args.config_dir, n)
        for n in os.listdir(args.config_dir)
        if n.startswith("eventStruct_") and n.endswith(".xml"))
    if not paths:
        raise SystemExit("no eventStruct_*.xml under %s" % args.config_dir)

    profiles = [load_profile(p) for p in paths]
    profiles.sort(key=lambda p: p["min_build"])
    known = property_name_vector()

    errors, warnings = [], []
    for profile in profiles:
        check_profile(profile, known, errors, warnings)

    if not args.quiet:
        print("profiles:")
        for p in profiles:
            print("  %-6s build %5d..%-5d %3d events  %s"
                  % (p["name"], p["min_build"], p["max_build"],
                     len(p["events"]), os.path.basename(p["path"])))

        if args.build is not None:
            # mirrors schema::SelectSchemaFile()
            best = None
            for p in profiles:
                if p["min_build"] > args.build:
                    continue
                if p["max_build"] and args.build > p["max_build"]:
                    continue
                if best is None or p["min_build"] > best["min_build"]:
                    best = p
            if best is None:
                best = min(profiles, key=lambda p: p["min_build"])
            print("")
            print("build %d -> profile %s (%s)"
                  % (args.build, best["name"], os.path.basename(best["path"])))

        print("")
        print("layouts (fixed bytes before the first variable field):")
        for p in profiles:
            print("  [%s]" % p["name"])
            for ev in sorted(p["events"], key=lambda e: e["name"]):
                prefix, variable, first_var = layout_size(ev["attrs"])
                print("    %-30s %5d%s"
                      % (ev["name"], prefix,
                         "  (variable from '%s')" % first_var if variable else ""))

    if args.sizes:
        for p in profiles:
            print("")
            print("### %s (%d..%d)" % (p["name"], p["min_build"], p["max_build"] or 0))
            print("")
            print("| event | provider | opcode | fixed prefix | variable from |")
            print("|---|---|---|---|---|")
            for ev in sorted(p["events"], key=lambda e: (e["provider"], e["opcode"])):
                prefix, variable, first_var = layout_size(ev["attrs"])
                print("| %s | %d | %d | %d | %s |"
                      % (ev["name"], ev["provider"], ev["opcode"], prefix,
                         first_var if variable else "-"))

    if args.probe:
        target = None
        for p in profiles:
            if args.profile and p["name"] != args.profile:
                continue
            target = p
            break
        if target is None:
            raise SystemExit("profile %r not found" % args.profile)
        notes = []
        for line in cross_check(target, args.probe, errors, notes):
            print(line)
        if notes:
            print("")
            print("notes:")
            for n in notes:
                print("  - " + n)

    if not args.quiet:
        print("")
        print("profile differences:")
        for line in compare_profiles(profiles):
            print(line)

    if warnings:
        print("")
        print("warnings (%d):" % len(warnings))
        for w in warnings:
            print("  ! " + w)

    if errors:
        print("")
        print("errors (%d):" % len(errors))
        for e in errors:
            print("  x " + e)
        return 1

    if not args.quiet:
        print("")
        print("OK: schema profiles are consistent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
