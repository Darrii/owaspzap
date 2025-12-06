# 🎯 Benchmark Scripts

Ready-to-run скрипты для тестирования Vulnerability Chain Detection системы на уязвимых приложениях.

## 📁 Файлы

```
benchmarks/
├── README.md                     # Эта инструкция
├── quick_start_dvwa.sh           # 🚀 Quick start для DVWA (всё в одном)
├── scan_dvwa.py                  # ZAP сканирование DVWA
├── analyze_results.py            # Анализ результатов
└── ground_truth/                 # Эталонные данные (для создания)
    ├── dvwa_chains.json
    ├── webgoat_chains.json
    └── juiceshop_chains.json
```

## 🚀 Quick Start (рекомендуется)

Самый простой способ - запустить готовый скрипт:

```bash
# Запустить полный DVWA бенчмарк
./benchmarks/quick_start_dvwa.sh
```

Скрипт автоматически:
1. ✅ Запускает DVWA и ZAP в Docker
2. ✅ Выполняет ZAP сканирование
3. ✅ Анализирует результаты
4. ✅ Создаёт HTML отчёт
5. ✅ Показывает метрики

## 📖 Пошаговое использование

### Шаг 1: Запуск уязвимого приложения

```bash
# Запустить DVWA
docker-compose up -d dvwa

# Настроить DVWA:
# 1. Открыть http://localhost:8080/setup.php
# 2. Create Database
# 3. Логин: admin / password
# 4. DVWA Security -> Low
```

### Шаг 2: Запуск ZAP

```bash
# Запустить ZAP
docker-compose up -d zap

# Подождать 10-15 секунд
sleep 15

# Проверить что ZAP работает
curl "http://localhost:8090/JSON/core/view/version/?apikey=changeme"
```

### Шаг 3: Сканирование

```bash
# Базовое сканирование
python3 benchmarks/scan_dvwa.py

# Или с параметрами
python3 benchmarks/scan_dvwa.py \
  --target http://dvwa:80 \
  --output scans/dvwa_scan.json \
  --spider-duration 5 \
  --scan-duration 15
```

**Параметры:**
- `--target` - URL для сканирования
- `--output` - Выходной файл
- `--spider-duration` - Время Spider scan (минуты)
- `--scan-duration` - Время Active scan (минуты)
- `--skip-spider` - Пропустить Spider scan
- `--skip-active` - Пропустить Active scan

### Шаг 4: Анализ результатов

```bash
# Базовый анализ (создаёт HTML и JSON)
python3 benchmarks/analyze_results.py \
  --input scans/dvwa_scan.json

# Или с явным указанием выходных файлов
python3 benchmarks/analyze_results.py \
  --input scans/dvwa_scan.json \
  --output-html reports/dvwa_chains.html \
  --output-json reports/dvwa_metrics.json
```

**Параметры:**
- `--input` - ZAP JSON отчёт
- `--output-html` - HTML отчёт (опционально)
- `--output-json` - JSON метрики (опционально)
- `--max-chain-length` - Макс. длина цепочки (по умолчанию: 5)
- `--min-confidence` - Мин. confidence 0-1 (по умолчанию: 0.5)
- `--min-risk` - Мин. уровень риска (Low/Medium/High)

### Шаг 5: Просмотр результатов

```bash
# macOS
open reports/dvwa_chains.html

# Linux
xdg-open reports/dvwa_chains.html

# Или просмотр JSON
cat reports/dvwa_metrics.json | python3 -m json.tool
```

## 🎯 Примеры использования

### Пример 1: Быстрый тест (5 минут)

```bash
# Короткое сканирование для теста
python3 benchmarks/scan_dvwa.py \
  --spider-duration 2 \
  --scan-duration 3 \
  --output scans/quick_test.json

python3 benchmarks/analyze_results.py \
  --input scans/quick_test.json
```

### Пример 2: Полное сканирование (30+ минут)

```bash
# Глубокое сканирование
python3 benchmarks/scan_dvwa.py \
  --spider-duration 15 \
  --scan-duration 30 \
  --output scans/full_scan.json

python3 benchmarks/analyze_results.py \
  --input scans/full_scan.json \
  --max-chain-length 10 \
  --min-confidence 0.6
```

### Пример 3: Только высокие риски

```bash
# Анализ только High и Critical уязвимостей
python3 benchmarks/analyze_results.py \
  --input scans/dvwa_scan.json \
  --min-risk High \
  --output-html reports/high_risk_chains.html
```

### Пример 4: WebGoat

```bash
# Запустить WebGoat
docker-compose up -d webgoat

# Сканировать (используйте порт 8081)
python3 benchmarks/scan_dvwa.py \
  --target http://webgoat:8080/WebGoat \
  --output scans/webgoat_scan.json

# Анализ
python3 benchmarks/analyze_results.py \
  --input scans/webgoat_scan.json \
  --output-html reports/webgoat_chains.html
```

## 🧪 Тестируемые приложения

### DVWA
- **URL:** http://localhost:8080
- **Логин:** admin / password
- **Сложность:** Low
- **Время сканирования:** ~10-15 минут

### WebGoat
- **URL:** http://localhost:8081/WebGoat
- **Создать аккаунт**
- **Время сканирования:** ~20-30 минут

### Juice Shop
- **URL:** http://localhost:3000
- **Без авторизации**
- **Время сканирования:** ~15-20 минут

## 📊 Структура выходных файлов

### ZAP Scan (JSON)
```json
[
  {
    "pluginid": "40018",
    "alert": "SQL Injection",
    "risk": "High",
    "confidence": "Medium",
    "url": "http://dvwa:80/vulnerabilities/sqli/",
    ...
  }
]
```

### Chain Detection Metrics (JSON)
```json
{
  "total_vulnerabilities": 15,
  "total_chains": 3,
  "critical_chains": 2,
  "high_risk_chains": 1,
  "analysis_time": 0.045,
  "chains": [...]
}
```

### HTML Report
Визуализация с:
- Граф цепочек уязвимостей
- Детали каждой цепочки
- Risk scores
- Exploitation steps

## 🛑 Остановка

```bash
# Остановить контейнеры
docker-compose stop

# Удалить контейнеры (сохраняет данные)
docker-compose down

# Удалить всё (включая данные)
docker-compose down -v
```

## ⚠️ Troubleshooting

### ZAP не подключается

```bash
# Проверить что ZAP запущен
docker ps | grep zap

# Проверить логи
docker logs zap

# Перезапустить
docker-compose restart zap
sleep 15
```

### DVWA не отвечает

```bash
# Проверить логи
docker logs dvwa

# Перезапустить
docker-compose restart dvwa
```

### Сканирование зависло

```bash
# Уменьшить время сканирования
python3 benchmarks/scan_dvwa.py \
  --spider-duration 3 \
  --scan-duration 5
```

### Нет уязвимостей

Убедитесь что в DVWA установлен **Security Level: Low**:
1. http://localhost:8080/security.php
2. Выбрать "Low"
3. Submit

## 📈 Ожидаемые результаты

### DVWA (Security: Low)
- **Уязвимостей:** 15-25
- **Цепочек:** 3-7
- **Типичные цепочки:**
  - SQL Injection → Authentication Bypass
  - XSS → CSRF
  - Path Traversal → Information Disclosure

### WebGoat
- **Уязвимостей:** 20-40
- **Цепочек:** 5-10

### Juice Shop
- **Уязвимостей:** 30-50
- **Цепочек:** 8-15

## 💡 Советы

1. **Первый запуск:** Используйте `quick_start_dvwa.sh`
2. **Тестирование:** Начните с коротких сканов (2-3 минуты)
3. **Продакшн:** Для публикации используйте полное сканирование (30+ минут)
4. **Ресурсы:** Выделите Docker минимум 4GB RAM
5. **Время:** Spider (5-10 мин) + Active scan (15-30 мин)

## 📚 Дополнительно

См. также:
- [BENCHMARK_SETUP.md](../BENCHMARK_SETUP.md) - Полная инструкция по настройке
- [docker-compose.yml](../docker-compose.yml) - Docker конфигурация
- [README.md](../README.md) - Главная документация проекта
