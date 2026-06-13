#!/usr/bin/env python3
"""
AuthGraph — Convert sigma/*.yml rules to Wazuh local_rules.xml

Usage:
  pip install pyyaml
  python sigma/scripts/convert_sigma_to_wazuh.py
  python sigma/scripts/convert_sigma_to_wazuh.py --sigma-dir ./sigma --output ./sigma/wazuh/local_rules.xml

Deploy on Wazuh manager:
  sudo cp sigma/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
  sudo systemctl restart wazuh-manager
  sudo /var/ossec/bin/wazuh-logtest
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("ERROR: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# Primary entry YAML files that duplicate suite folders — skip to avoid double rules
SKIP_FILES = {
    "kerberoasting.yml",
    "asreproasting.yml",
    "golden-ticket.yml",
    "brute-force.yml",
}

# Sigma → Wazuh dynamic fields (EventChannel). Do NOT use static names
# (dstuser, srcip, status) in <field> — analysisd rejects them.
FIELD_MAP = {
    "EventID": "win.system.eventID",
    "TargetUserName": "win.eventdata.targetUserName",
    "TargetDomainName": "win.eventdata.targetDomainName",
    "ServiceName": "win.eventdata.serviceName",
    "TicketEncryptionType": "win.eventdata.ticketEncryptionType",
    "TicketOptions": "win.eventdata.ticketOptions",
    "IpAddress": "win.eventdata.ipAddress",
    "WorkstationName": "win.eventdata.workstationName",
    "Status": "win.eventdata.status",
    "SubStatus": "win.eventdata.subStatus",
    "LogonType": "win.eventdata.logonType",
    "PreAuthType": "win.eventdata.preAuthType",
    "CommandLine": "win.eventdata.commandLine",
    "ScriptBlockText": "win.eventdata.scriptBlockText",
    "NewProcessName": "win.eventdata.processName",
    "ParentProcessName": "win.eventdata.parentProcessName",
    "Properties": "win.eventdata.properties",
    "SubjectUserName": "win.eventdata.subjectUserName",
    "AccessMask": "win.eventdata.accessMask",
}

LEVEL_MAP = {
    "informational": 3,
    "low": 6,
    "medium": 10,
    "high": 12,
    "critical": 15,
}

CORRELATION_RE = re.compile(
    r"\|\s*count(?:_distinct)?\(([^)]*)\)\s*by\s+([^>]+?)\s*>\s*(\d+)",
    re.IGNORECASE,
)

TIMEFRAME_RE = re.compile(r"^(\d+)(s|m|h|d)$", re.IGNORECASE)


def escape_regex(value: str) -> str:
    return re.escape(str(value))


def parse_timeframe(value: str | None) -> int:
    if not value:
        return 300
    m = TIMEFRAME_RE.match(str(value).strip())
    if not m:
        return 300
    n, unit = int(m.group(1)), m.group(2).lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return n * mult.get(unit, 60)


def wazuh_field(sigma_key: str) -> tuple[str, str | None]:
    """Return (wazuh_field, modifier) from 'Field|contains'."""
    if "|" in sigma_key:
        field, mod = sigma_key.split("|", 1)
        base = field.split(".")[-1]
        mapped = FIELD_MAP.get(field) or FIELD_MAP.get(base) or base[0].lower() + base[1:]
        return mapped, mod
    return FIELD_MAP.get(sigma_key, sigma_key[0].lower() + sigma_key[1:]), None


def values_to_regex(values: Any, modifier: str | None) -> str:
    if values is None:
        return ""
    items = values if isinstance(values, list) else [values]

    if modifier == "contains":
        parts = [escape_regex(v) for v in items if v is not None]
        return "|".join(parts)
    if modifier == "endswith":
        v = items[0] if items else ""
        return escape_regex(v) + "$"
    if modifier == "startswith":
        v = items[0] if items else ""
        return "^" + escape_regex(v)

    # exact match — expand hex to upper+lower (Wazuh OSRegex may not support (?i:))
    parts = []
    for v in items:
        if v == "":
            parts.append("^$")
        elif isinstance(v, int):
            parts.append(f"^{v}$")
        else:
            s = str(v)
            if s in ("::1",):
                continue
            if s in ("-", ""):
                parts.append("^-$|^$")
                continue
            if re.match(r"^0x[0-9a-fA-F]+$", s):
                low = s.lower()
                high = s.upper()
                parts.append(f"^{escape_regex(low)}$")
                if high != low:
                    parts.append(f"^{escape_regex(high)}$")
            else:
                parts.append(f"^{escape_regex(s)}$")
    return "|".join(parts)


class RuleIdGen:
    """Sequential unique Wazuh rule IDs (avoid hash collisions)."""

    def __init__(self, start: int = 100100) -> None:
        self._next = start
        self.used: set[int] = set()

    def allocate(self) -> int:
        while self._next in self.used:
            self._next += 1
        rid = self._next
        self.used.add(rid)
        self._next += 1
        return rid


def merge_field_criteria(
    criteria: list[tuple[str, str, bool]],
) -> list[tuple[str, str, bool]]:
    """Merge multiple regexes on the same field+negate into one OR pattern."""
    buckets: dict[tuple[str, bool], list[str]] = {}
    for wfield, regex, negate in criteria:
        if not regex:
            continue
        key = (wfield, negate)
        buckets.setdefault(key, []).append(regex)

    out: list[tuple[str, str, bool]] = []
    for (wfield, negate), patterns in buckets.items():
        if len(patterns) == 1:
            out.append((wfield, patterns[0], negate))
            continue
        anchored = all(p.startswith("^") and p.endswith("$") for p in patterns)
        if anchored:
            inner = "|".join(p[1:-1] for p in patterns)
            out.append((wfield, f"^{inner}$", negate))
        else:
            out.append((wfield, "|".join(patterns), negate))
    return out


def extract_mitre_tags(tags: list[str] | None) -> list[str]:
    if not tags:
        return []
    out = []
    for t in tags:
        if not t.startswith("attack."):
            continue
        # Wazuh expects e.g. T1558.003 not T1558_003
        tid = t.replace("attack.", "").upper().replace("_", ".")
        if tid.startswith("T") and tid not in out:
            out.append(tid)
    return out


def parse_condition(condition: str, detection: dict) -> dict:
    cond = condition.strip()
    corr = CORRELATION_RE.search(cond)
    correlation = None
    if corr:
        correlation = {
            "count_field": corr.group(1).strip() or None,
            "distinct": "count_distinct" in cond.lower(),
            "by_fields": [f.strip() for f in corr.group(2).split(",")],
            "threshold": int(corr.group(3)),
        }
        cond = cond[: corr.start()].strip()

    include_blocks: list[str] = []
    exclude_blocks: list[str] = []

    # selection and filter_x and not 1 of filter_a, filter_b
    one_of_filters = re.search(r"\b1 of filter_\*", cond)

    if re.search(r"\b1 of selection_\*", cond):
        include_blocks = [k for k in detection if k.startswith("selection_")]
    elif one_of_filters:
        include_blocks = ["selection"] if "selection" in detection else []
    else:
        for part in re.split(r"\band\b", cond, flags=re.IGNORECASE):
            part = part.strip()
            if not part or part.startswith("|"):
                continue
            if part.startswith("not "):
                inner = part[4:].strip()
                if inner.startswith("1 of "):
                    refs = inner[5:].strip()
                    if refs == "filter_*":
                        exclude_blocks.extend(k for k in detection if k.startswith("filter_"))
                    else:
                        exclude_blocks.extend(r.strip() for r in refs.split(","))
                else:
                    exclude_blocks.append(inner)
            elif part.startswith("1 of filter_"):
                pass
            elif part in detection:
                include_blocks.append(part)
            elif part == "selection":
                include_blocks.append("selection")

    if not include_blocks:
        if "selection" in detection:
            include_blocks = ["selection"]
        else:
            include_blocks = [k for k in detection if k.startswith("selection")]

    return {
        "include": include_blocks,
        "exclude": exclude_blocks,
        "correlation": correlation,
        "one_of_filters": bool(one_of_filters),
    }


def merge_detection_blocks(detection: dict, block_names: list[str]) -> list[tuple[str, str, bool]]:
    """
    Merge field criteria into list of (wazuh_field, regex, negate).
    OR across selection_* blocks for '1 of selection_*'.
    """
    criteria: list[tuple[str, str, bool]] = []

    for block in block_names:
        block_data = detection.get(block, {})
        if not isinstance(block_data, dict):
            continue
        for sigma_key, value in block_data.items():
            wfield, mod = wazuh_field(sigma_key)
            regex = values_to_regex(value, mod)
            if regex:
                criteria.append((wfield, regex, False))

    return criteria


def dedupe_criteria(criteria: list[tuple[str, str, bool]]) -> list[tuple[str, str, bool]]:
    seen = set()
    out = []
    for item in criteria:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def group_or_selections(detection: dict, block_names: list[str]) -> list[list[tuple[str, str, bool]]]:
    """For 1 of selection_* — each block is an OR branch."""
    if len(block_names) <= 1:
        return [merge_detection_blocks(detection, block_names)]
    return [merge_detection_blocks(detection, [b]) for b in block_names]


def add_field_criterion(
    rule: ET.Element, wfield: str, regex: str, negate: bool
) -> None:
    """Append a field match; win.eventdata.* fields use pcre2."""
    field_el = ET.SubElement(rule, "field", name=wfield)
    if wfield.startswith("win."):
        field_el.set("type", "pcre2")
    if negate:
        field_el.set("negate", "yes")
    field_el.text = regex


def build_rule_element(
    rule_id: int,
    level: int,
    description: str,
    criteria: list[tuple[str, str, bool]],
    if_sid: int | None = None,
    if_matched_sid: int | None = None,
    frequency: int | None = None,
    timeframe: int | None = None,
    same_fields: list[str] | None = None,
    different_fields: list[str] | None = None,
    mitre: list[str] | None = None,
    use_windows_group: bool = True,
) -> ET.Element:
    rule = ET.Element("rule", id=str(rule_id), level=str(level))

    if if_matched_sid:
        rule.set("frequency", str(frequency or 5))
        rule.set("timeframe", str(timeframe or 300))
        child = ET.SubElement(rule, "if_matched_sid")
        child.text = str(if_matched_sid)
    elif if_sid:
        child = ET.SubElement(rule, "if_sid")
        child.text = str(if_sid)
    elif use_windows_group:
        child = ET.SubElement(rule, "if_group")
        child.text = "windows,"

    for wfield, regex, negate in criteria:
        add_field_criterion(rule, wfield, regex, negate)

    if same_fields:
        for sf in same_fields:
            el = ET.SubElement(rule, "same_field")
            el.text = sf

    if different_fields:
        for df in different_fields:
            el = ET.SubElement(rule, "different_field")
            el.text = df

    desc = ET.SubElement(rule, "description")
    desc.text = description

    if mitre:
        mitre_el = ET.SubElement(rule, "mitre")
        for mid in mitre:
            id_el = ET.SubElement(mitre_el, "id")
            id_el.text = mid

    return rule


def convert_sigma_rule(rule: dict, source_file: str, id_gen: RuleIdGen) -> list[ET.Element]:
    detection = rule.get("detection") or {}
    condition = detection.get("condition", "selection")
    if not condition:
        return []

    parsed = parse_condition(str(condition), detection)
    title = rule.get("title", source_file)
    sigma_id = rule.get("id", source_file)
    level = LEVEL_MAP.get(str(rule.get("level", "medium")).lower(), 10)
    timeframe = parse_timeframe(detection.get("timeframe"))
    mitre = extract_mitre_tags(rule.get("tags"))

    elements: list[ET.Element] = []
    base_id = id_gen.allocate()
    alert_id = id_gen.allocate()

    # OR selections → merge into one rule (avoid orphan branch IDs)
    is_or_selection = any(
        b.startswith("selection_") for b in parsed["include"]
    ) and len(parsed["include"]) > 1

    include_criteria = merge_detection_blocks(detection, parsed["include"])
    exclude_criteria = merge_detection_blocks(detection, parsed["exclude"])

    if is_or_selection:
        branches = group_or_selections(detection, parsed["include"])
        merged_or: dict[str, list[str]] = {}
        for branch in branches:
            for wfield, regex, _ in branch:
                merged_or.setdefault(wfield, []).append(regex)
        include_criteria = [(f, "|".join(rs), False) for f, rs in merged_or.items()]
        base_id = id_gen.allocate()
        alert_id = id_gen.allocate()

    all_include = dedupe_criteria(include_criteria)
    all_criteria = merge_field_criteria(
        all_include + [(f, r, True) for f, r, _ in exclude_criteria]
    )

    if not all_criteria and not parsed.get("correlation"):
        return []

    correlation = parsed["correlation"]

    if parsed.get("one_of_filters"):
        filter_blocks = [k for k in detection if k.startswith("filter_")]
        for fb in filter_blocks:
            crit = merge_field_criteria(
                dedupe_criteria(
                    merge_detection_blocks(detection, parsed["include"])
                    + merge_detection_blocks(detection, [fb])
                    + [(f, r, True) for f, r, _ in exclude_criteria]
                )
            )
            if not crit:
                continue
            elements.append(
                build_rule_element(
                    id_gen.allocate(),
                    level,
                    f"AuthGraph: {title} ({fb})",
                    crit,
                    mitre=mitre,
                )
            )
        return elements

    if correlation:
        child_id = id_gen.allocate()
        parent_id = id_gen.allocate()
        child = build_rule_element(
            child_id,
            3,
            f"AuthGraph [child]: {title} ({Path(source_file).name})",
            all_criteria,
            mitre=None,
        )
        elements.append(child)

        same_fields = []
        different_fields = []
        for sigma_field in correlation["by_fields"]:
            wf, _ = wazuh_field(sigma_field.strip())
            same_fields.append(wf)

        if correlation["distinct"] and correlation["count_field"]:
            wf, _ = wazuh_field(correlation["count_field"].strip())
            different_fields.append(wf)

        parent = build_rule_element(
            parent_id,
            level,
            f"AuthGraph: {title}",
            [],
            if_matched_sid=child_id,
            frequency=correlation["threshold"],
            timeframe=timeframe,
            same_fields=same_fields,
            different_fields=different_fields,
            mitre=mitre,
            use_windows_group=False,
        )
        elements.append(parent)
    else:
        elements.append(
            build_rule_element(
                id_gen.allocate(),
                level,
                f"AuthGraph: {title}",
                all_criteria,
                mitre=mitre,
            )
        )

    return elements


def collect_yaml_files(sigma_dir: Path) -> list[Path]:
    files = sorted(sigma_dir.rglob("*.yml"))
    out = []
    for f in files:
        if f.name in SKIP_FILES:
            continue
        out.append(f)
    return out


def prettify_xml(root: ET.Element) -> str:
    """Wazuh rules must NOT include <?xml ?> declaration — parser rejects it."""
    ET.indent(root, space="  ")
    xml_str = ET.tostring(root, encoding="unicode")
    return (
        "<!-- AuthGraph rules - auto-generated by convert_sigma_to_wazuh.py -->\n"
        + xml_str
        + "\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert AuthGraph Sigma YAML to Wazuh XML")
    parser.add_argument(
        "--sigma-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Path to sigma/ directory (default: repo sigma/)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "wazuh" / "authgraph_rules.xml",
        help="Output XML path (default: authgraph_rules.xml)",
    )
    args = parser.parse_args()

    sigma_dir = args.sigma_dir.resolve()
    if not sigma_dir.is_dir():
        print(f"ERROR: sigma dir not found: {sigma_dir}", file=sys.stderr)
        return 1

    yaml_files = collect_yaml_files(sigma_dir)
    if not yaml_files:
        print(f"ERROR: no .yml files in {sigma_dir}", file=sys.stderr)
        return 1

    group = ET.Element("group", name="authgraph,identity_attacks,")
    id_gen = RuleIdGen(100100)
    converted = 0
    skipped = 0
    errors: list[str] = []

    for ypath in yaml_files:
        try:
            with open(ypath, encoding="utf-8") as fh:
                rule = yaml.safe_load(fh)
            if not rule or not isinstance(rule, dict):
                skipped += 1
                continue
            if not rule.get("detection"):
                skipped += 1
                continue
            for el in convert_sigma_rule(rule, str(ypath.relative_to(sigma_dir)), id_gen):
                group.append(el)
                converted += 1
        except Exception as exc:
            errors.append(f"{ypath.name}: {exc}")

    if converted == 0:
        print("ERROR: no rules generated", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(prettify_xml(group), encoding="utf-8")

    print(f"Sigma dir:  {sigma_dir}")
    print(f"YAML files: {len(yaml_files)} (skipped entries: {', '.join(sorted(SKIP_FILES))})")
    print(f"Wazuh rules generated: {converted}")
    print(f"Rule ID range: 100100–{id_gen._next - 1}")
    print(f"Output: {args.output}")
    print()
    print("Deploy on Wazuh manager:")
    print(f"  sudo cp {args.output} /var/ossec/etc/rules/authgraph_rules.xml")
    print("  # loads automatically via <rule_dir>etc/rules</rule_dir> in ossec.conf")
    print("  sudo /var/ossec/bin/wazuh-analysisd -t")
    print("  sudo systemctl restart wazuh-manager")

    if errors:
        print("\nWarnings/errors:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
