#!/usr/bin/env python3
import requests
import time
import csv
import os
from getpass import getpass
from datetime import datetime

def prompt_input(prompt_text):
    while True:
        value = input(prompt_text).strip()
        if value:
            return value
        print("❗ Bu alan boş bırakılamaz. Lütfen geçerli bir değer girin.")

def prompt_secure_input(prompt_text):
    while True:
        value = getpass(prompt_text).strip()
        if value:
            return value
        print("❗ Bu alan boş bırakılamaz. Lütfen geçerli bir değer girin.")

# === Kullanıcı Girdisi ===
QRADAR_HOST = prompt_input("QRadar Host (örnek: 192.168.1.2): ")
API_TOKEN = prompt_secure_input("API Token (gizli girilecek): ")
start_date_str = prompt_input("Başlangıç tarihi (YYYY-MM-DD): ")
output_path = prompt_input("Çıktıların kaydedileceği dizin (örnek: /opt/test): ")

# Dizin varsa yoksa oluştur
if not os.path.exists(output_path):
    os.makedirs(output_path)

# Tarih string'ini epoch timestamp'e çevir
try:
    start_date_obj = datetime.strptime(start_date_str, "%Y-%m-%d")
    start_time_epoch = int(start_date_obj.timestamp())
except ValueError:
    print("❌ Hatalı tarih formatı! Lütfen YYYY-MM-DD şeklinde girin.")
    exit(1)

# === Config ===
QRADAR_URL = f"https://{QRADAR_HOST}/"

headers = {
    'SEC': API_TOKEN,
    'Version': '12.0',
    'Accept': 'application/json'
}

requests.packages.urllib3.disable_warnings()

inactive_rules_path = os.path.join(output_path, "inactive_rules.csv")

# === 1. Adım: Tüm USER ve ENABLED kuralları çek ===
rules_url = f'{QRADAR_URL}/api/analytics/rules?filter=enabled=true AND origin="USER"'
rules_resp = requests.get(rules_url, headers=headers, verify=False)

if rules_resp.status_code != 200:
    print("❌ Kurallar çekilemedi:", rules_resp.status_code, rules_resp.text)
    exit(1)

all_rules = sorted({
    rule['name'].strip()
    for rule in rules_resp.json()
})

# === 2. Adım: Belirli start_time sonrası tetiklenen kurallar ===
offenses_url = f'{QRADAR_URL}/api/siem/offenses?filter=categories CONTAINS "Device Information" AND start_time>{start_time_epoch}'
offenses_resp = requests.get(offenses_url, headers=headers, verify=False)

if offenses_resp.status_code != 200:
    print("❌ Offense'lar çekilemedi:", offenses_resp.status_code, offenses_resp.text)
    exit(1)

triggered_rules = sorted({
    off['description'].strip()
    for off in offenses_resp.json()
})

# === 3. Adım: Tetiklenmemiş kuralları ayıkla ===
inactive_rules = sorted(set(all_rules) - set(triggered_rules))

# === 4. Adım: CSV yazma fonksiyonu ===
def write_csv(filename, title, data):
    with open(filename, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([title])
        for item in data:
            writer.writerow([item])

write_csv(os.path.join(output_path, "all_rules.csv"), "All Rules", all_rules)
write_csv(os.path.join(output_path, "triggered_rules.csv"), "Triggered Rules", triggered_rules)
write_csv(inactive_rules_path, "Inactive Rules", inactive_rules)

print("\n✅ Tamamlandı. Oluşan CSV dosyaları:")
print(f"- {os.path.join(output_path, 'all_rules.csv')}")
print(f"- {os.path.join(output_path, 'triggered_rules.csv')}")
print(f"- {inactive_rules_path}")
