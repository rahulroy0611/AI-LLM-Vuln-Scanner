import json
import pandas as pd
import sys
from pathlib import Path


def load_plugin(plugin_path):
    with open(plugin_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_plugin(plugin_path, plugin_data):
    with open(plugin_path, "w", encoding="utf-8") as f:
        json.dump(plugin_data, f, indent=2, ensure_ascii=False)


def parse_list(value):
    if pd.isna(value):
        return []
    return [v.strip() for v in str(value).split(",") if v.strip()]


def normalize_prompt(prompt: str) -> str:
    """Normalize prompt for duplicate comparison"""
    return " ".join(prompt.lower().split())


def update_plugin(plugin_path, excel_path):
    plugin = load_plugin(plugin_path)
    df = pd.read_excel(excel_path)

    required_cols = [
        "id",
        "category",
        "prompt",
        "failed_keywords",
        "compliance(OWASP)",
        "compliance(DPDP)",
        "compliance(GDPR)",
        "compliance(ISO27001)"
    ]

    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column in Excel: {col}")

    existing_tests = plugin.get("tests", [])

    existing_ids = {t["id"] for t in existing_tests}
    existing_prompts = {
        normalize_prompt(t.get("prompt", ""))
        for t in existing_tests
    }

    added = 0
    duplicate_id = 0
    duplicate_prompt = 0

    new_tests = []

    for _, row in df.iterrows():
        test_id = str(row["id"]).strip()
        prompt = str(row["prompt"]).strip()

        norm_prompt = normalize_prompt(prompt)

        # Duplicate ID check
        if test_id in existing_ids:
            duplicate_id += 1
            continue

        # Duplicate prompt check
        if norm_prompt in existing_prompts:
            duplicate_prompt += 1
            continue

        test = {
            "id": test_id,
            "category": str(row["category"]).strip(),
            "prompt": prompt,
            "fail_keywords": parse_list(row["failed_keywords"]),
            "compliance": {
                "OWASP": parse_list(row["compliance(OWASP)"]),
                "DPDP": parse_list(row["compliance(DPDP)"]),
                "GDPR": parse_list(row["compliance(GDPR)"]),
                "ISO27001": parse_list(row["compliance(ISO27001)"])
            }
        }

        new_tests.append(test)

        existing_ids.add(test_id)
        existing_prompts.add(norm_prompt)
        added += 1

    if new_tests:
        plugin["tests"].extend(new_tests)
        save_plugin(plugin_path, plugin)

    # 📊 Summary Report
    print("\n========= PLUGIN UPDATE SUMMARY =========")
    print(f"✅ New prompts added      : {added}")
    print(f"❌ Rejected (duplicate ID): {duplicate_id}")
    print(f"❌ Rejected (duplicate prompt): {duplicate_prompt}")
    print(f"📦 Total tests in plugin  : {len(plugin['tests'])}")
    print("========================================\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python update_plugin_from_excel.py <plugin.json> <tests.xlsx>")
        sys.exit(1)

    plugin_file = Path(sys.argv[1])
    excel_file = Path(sys.argv[2])

    if not plugin_file.exists():
        raise FileNotFoundError(f"Plugin file not found: {plugin_file}")

    if not excel_file.exists():
        raise FileNotFoundError(f"Excel file not found: {excel_file}")

    update_plugin(plugin_file, excel_file)
