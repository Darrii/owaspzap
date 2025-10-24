import json
import pandas as pd

# Путь к JSON файлу
json_path = 'report_scan_20250519_161500_20250519_161507.json'

# Загружаем JSON
with open(json_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

# Берём список алертов
alerts = data.get('alerts', [])

# Формируем список словарей с нужными полями
rows = []
for alert in alerts:
    row = {
        'alert': alert.get('alert'),
        'url': alert.get('url'),
        'param': alert.get('param'),
        'risk': alert.get('risk'),
        'base_score': alert.get('base_score'),
        'exploitability_score': alert.get('exploitability_score'),
        'impact_score': alert.get('impact_score'),
        'temporal_score': alert.get('temporal_score'),
        'environmental_score': alert.get('environmental_score'),
        'priority_score': alert.get('priority_score'),
    }
    rows.append(row)

# Создаём DataFrame
df = pd.DataFrame(rows)

# Сохраняем в Excel
df.to_excel('alerts_report_7.xlsx', index=False)

print("Готово! Файл alerts_report.xlsx создан.")
