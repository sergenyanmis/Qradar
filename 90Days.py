#!/usr/bin/env python3
import requests
import time
import csv
import os

# === Config ===
QRADAR_HOST = "Qradar_IP"
API_TOKEN = "Token_Information"

QRADAR_URL = f"https://{QRADAR_HOST}/"

headers = {
    'SEC': API_TOKEN,
    'Version': '12.0',
    'Accept': 'application/json'
}

requests.packages.urllib3.disable_warnings()

# Mevcut dosya varsa sil
inactive_rules_path = "/opt/inactive_rules.csv"
if os.path.exists(inactive_rules_path):
    os.remove(inactive_rules_path)

# 90 gün önceki epoch timestamp (saniye cinsinden)
ninety_days_ago = int(time.time() - 90 * 24 * 60 * 60)

# === 1. Adım: Tüm USER ve ENABLED kuralları çek ===
rules_url = f'{QRADAR_URL}/api/analytics/rules?filter=enabled=true AND origin="USER"'
rules_resp = requests.get(rules_url, headers=headers, verify=False)
all_rules = rules_resp.json()

# Tüm kuralları temizleyerek listele
all_rule_names = sorted({
    rule['name'].strip()
    for rule in all_rules
})

# === 2. Adım: Son 90 günde tetiklenen kurallar ===
offenses_url = f'{QRADAR_URL}/api/siem/offenses?filter=categories CONTAINS "Triage" AND start_time>{ninety_days_ago}'
offenses_resp = requests.get(offenses_url, headers=headers, verify=False)
offenses = offenses_resp.json()

# Offense description'ları al ve temizle
triggered_rule_names = sorted({
    off['description'].strip()
    for off in offenses
})

# === 3. Adım: Tetiklenmemiş (inactive) kurallar ===
inactive_rules = sorted(set(all_rule_names) - set(triggered_rule_names))

# === 4. Adım: CSV Dosyalarına Yaz ===
def write_csv(filename, title, data):
    with open(filename, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([title])
        for item in data:
            writer.writerow([item])

write_csv("all_rules.csv", "All Rules", all_rule_names)
write_csv("triggered_rules.csv", "Triggered Rules (Last 90 Days)", triggered_rule_names)
write_csv(inactive_rules_path, "Inactive Rules (Last 90 Days)", inactive_rules)

print("Tamamlandı. Oluşan CSV dosyaları:")
print("- all_rules.csv")
print("- triggered_rules.csv")
print(f"- {inactive_rules_path}")
