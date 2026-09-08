import yara
import os
from ..config import settings

def load_yara_rules():
    rules = {}
    rules_dir = settings.YARA_RULES_DIR
    if not os.path.exists(rules_dir):
        return None
    for filename in os.listdir(rules_dir):
        if filename.endswith('.yar') or filename.endswith('.yara'):
            rule_path = os.path.join(rules_dir, filename)
            try:
                compiled = yara.compile(filepath=rule_path)
                rules[filename] = compiled
            except Exception as e:
                print(f"Error compiling {filename}: {e}")
    return rules if rules else None

def scan_with_yara(file_path):
    rules = load_yara_rules()
    if not rules:
        return []
    matches = []
    for rule_name, rule in rules.items():
        try:
            rule_matches = rule.match(file_path)
            for m in rule_matches:
                matches.append({
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": m.tags,
                    "meta": m.meta,
                    "strings": [str(s) for s in m.strings]
                })
        except Exception as e:
            print(f"Error scanning with {rule_name}: {e}")
    return matches