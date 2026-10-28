"""Loads probe suites from YAML into Probe objects."""

import yaml

from backend.attack.models import MEDIUM, SEVERITY_VALUES, Probe


def load_probes(path):
    """Reads a probe suite file and returns a list of Probe objects."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    probes = []
    for item in data.get("probes", []):
        probes.append(Probe(
            probe_id=item["probe_id"],
            category=item["category"],
            description=item["description"],
            payload=item["payload"],
            detect=item["detect"],
            # Severity is written as a name ("HIGH") in YAML; fall back to MEDIUM.
            severity=SEVERITY_VALUES.get(item.get("severity", "MEDIUM"), MEDIUM),
        ))
    return probes
