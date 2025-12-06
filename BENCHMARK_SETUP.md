# 🎯 Benchmark Testing Setup Guide

Полное руководство по запуску бенчмарк-тестирования системы Vulnerability Chain Detection с использованием Docker, OWASP ZAP и уязвимых приложений.

## 📋 Содержание

1. [Требования](#требования)
2. [Установка Docker и ZAP](#установка-docker-и-zap)
3. [Запуск уязвимых приложений](#запуск-уязвимых-приложений)
4. [Запуск ZAP сканирования](#запуск-zap-сканирования)
5. [Анализ результатов](#анализ-результатов)
6. [Готовые скрипты](#готовые-скрипты)

---

## 🔧 Требования

### Минимальные требования

- **OS:** macOS, Linux, или Windows с WSL2
- **RAM:** 8GB минимум, 16GB рекомендуется
- **Disk:** 10GB свободного места
- **Docker:** версия 20.10+
- **Docker Compose:** версия 2.0+
- **Python:** 3.8+

### Проверка установленных компонентов

```bash
# Проверить Docker
docker --version
docker-compose --version

# Проверить Python
python3 --version
pip3 --version
```

---

## 🐳 Установка Docker и ZAP

### macOS

```bash
# 1. Установить Docker Desktop
# Скачать с https://www.docker.com/products/docker-desktop

# 2. После установки проверить
docker run hello-world

# 3. Установить Python зависимости
pip3 install -r requirements.txt
```

### Linux (Ubuntu/Debian)

```bash
# 1. Установить Docker
sudo apt-get update
sudo apt-get install -y docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker

# 2. Добавить пользователя в группу docker
sudo usermod -aG docker $USER
newgrp docker

# 3. Проверить установку
docker run hello-world

# 4. Установить Python зависимости
pip3 install -r requirements.txt
```

### Windows (WSL2)

```powershell
# 1. Установить WSL2
wsl --install

# 2. Установить Docker Desktop for Windows
# Скачать с https://www.docker.com/products/docker-desktop

# 3. В WSL2 терминале
pip3 install -r requirements.txt
```

---

## 🎮 Запуск уязвимых приложений

### Вариант 1: DVWA (Damn Vulnerable Web Application)

```bash
# Запустить DVWA в Docker
docker run -d \
  --name dvwa \
  -p 8080:80 \
  vulnerables/web-dvwa

# Проверить что запустилось
docker ps | grep dvwa

# Открыть в браузере: http://localhost:8080
# Логин: admin / Пароль: password

# Настроить DVWA:
# 1. Открыть http://localhost:8080/setup.php
# 2. Нажать "Create / Reset Database"
# 3. Логин с admin/password
# 4. Установить Security Level: Low (DVWA Security -> Low)
```

### Вариант 2: WebGoat

```bash
# Запустить WebGoat в Docker
docker run -d \
  --name webgoat \
  -p 8081:8080 \
  -p 9090:9090 \
  webgoat/webgoat

# Проверить
docker ps | grep webgoat

# Открыть: http://localhost:8081/WebGoat
# Создать аккаунт и войти
```

### Вариант 3: OWASP Juice Shop

```bash
# Запустить Juice Shop в Docker
docker run -d \
  --name juice-shop \
  -p 3000:3000 \
  bkimminich/juice-shop

# Проверить
docker ps | grep juice-shop

# Открыть: http://localhost:3000
```

### Docker Compose - запуск всех сразу

Используйте готовый `docker-compose.yml`:

```bash
# Запустить все уязвимые приложения
docker-compose up -d

# Проверить статус
docker-compose ps

# Остановить все
docker-compose down
```

---

## 🔍 Запуск ZAP сканирования

### Вариант 1: ZAP в Docker (Headless)

```bash
# Запустить ZAP в режиме daemon
docker run -u zap -p 8090:8090 \
  --name zap \
  -d \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -port 8090 -host 0.0.0.0 -config api.key=changeme

# Подождать 10-15 секунд пока ZAP запустится
sleep 15

# Проверить что ZAP запущен
curl http://localhost:8090/JSON/core/view/version/?apikey=changeme
```

### Вариант 2: Использовать готовый скрипт

```bash
# Запустить автоматический бенчмарк для DVWA
python3 benchmarks/run_dvwa_benchmark.py

# Для WebGoat
python3 benchmarks/run_webgoat_benchmark.py

# Для Juice Shop
python3 benchmarks/run_juiceshop_benchmark.py
```

### Ручное сканирование через ZAP CLI

```bash
# Установить ZAP Python клиент
pip3 install python-owasp-zap-v2.4

# Запустить базовый Spider scan
python3 -c "
from zapv2 import ZAPv2

zap = ZAPv2(apikey='changeme', proxies={'http': 'http://localhost:8090'})

# Spider сканирование DVWA
target = 'http://host.docker.internal:8080'
zap.spider.scan(target)

# Подождать завершения
import time
while int(zap.spider.status()) < 100:
    print(f'Spider progress: {zap.spider.status()}%')
    time.sleep(2)

# Active scan
zap.ascan.scan(target)
while int(zap.ascan.status()) < 100:
    print(f'Active scan progress: {zap.ascan.status()}%')
    time.sleep(5)

# Сохранить результаты
import json
alerts = zap.core.alerts()
with open('dvwa_scan.json', 'w') as f:
    json.dump(alerts, f, indent=2)
print('Scan saved to dvwa_scan.json')
"
```

---

## 📊 Анализ результатов

### Анализ ZAP отчёта

После того как ZAP создал JSON отчёт, проанализируйте его:

```bash
# Анализ с Vulnerability Chain Detection
python3 -c "
from vulnerability_chains import VulnerabilityChainAnalyzer

analyzer = VulnerabilityChainAnalyzer()

# Анализировать ZAP отчёт
result = analyzer.analyze_zap_report(
    report_file='dvwa_scan.json',
    max_chain_length=5,
    min_confidence=0.5,
    min_risk_filter='Low'
)

# Вывести результаты
print(f'Найдено уязвимостей: {result.total_vulnerabilities}')
print(f'Найдено цепочек: {result.total_chains}')
print(f'Критических: {result.critical_chains}')
print(f'High risk: {result.high_risk_chains}')

# Сгенерировать HTML отчёт
analyzer.generate_report(result, output_file='dvwa_chains.html', format='html')
print('HTML отчёт создан: dvwa_chains.html')
"
```

### Создание ground truth и метрик

```bash
# Запустить полный бенчмарк с метриками
python3 benchmarks/benchmark_dvwa.py

# Результаты будут в:
# - benchmarks/dvwa_chains.html - визуализация
# - benchmarks/dvwa_metrics.json - метрики
```

---

## 🚀 Готовые скрипты

### Quick Start - всё в одной команде

```bash
# 1. Запустить DVWA + ZAP
./benchmarks/quick_start_dvwa.sh

# Скрипт автоматически:
# - Запускает DVWA в Docker
# - Запускает ZAP
# - Выполняет сканирование
# - Анализирует результаты
# - Создаёт отчёты
# - Останавливает контейнеры
```

### Пошаговый процесс

```bash
# Шаг 1: Запуск уязвимого приложения
docker-compose up -d dvwa

# Шаг 2: Запуск ZAP
docker-compose up -d zap

# Шаг 3: Подождать запуск (30 сек)
sleep 30

# Шаг 4: Запустить сканирование
python3 benchmarks/scan_dvwa.py

# Шаг 5: Проанализировать результаты
python3 benchmarks/analyze_results.py \
  --input scans/dvwa_scan.json \
  --output reports/dvwa_chains.html

# Шаг 6: Остановить всё
docker-compose down
```

---

## 📁 Структура файлов после запуска

```
owaspzap/
├── benchmarks/
│   ├── quick_start_dvwa.sh          # Quick start скрипт
│   ├── run_dvwa_benchmark.py        # DVWA бенчмарк
│   ├── run_webgoat_benchmark.py     # WebGoat бенчмарк
│   ├── run_juiceshop_benchmark.py   # Juice Shop бенчмарк
│   ├── scan_dvwa.py                 # ZAP сканирование DVWA
│   ├── analyze_results.py           # Анализ результатов
│   └── ground_truth/                # Эталонные данные
│       ├── dvwa_chains.json
│       ├── webgoat_chains.json
│       └── juiceshop_chains.json
├── scans/                            # ZAP сканы (создаётся)
│   ├── dvwa_scan.json
│   ├── webgoat_scan.json
│   └── juiceshop_scan.json
├── reports/                          # Отчёты (создаётся)
│   ├── dvwa_chains.html
│   ├── dvwa_metrics.json
│   ├── webgoat_chains.html
│   └── juiceshop_chains.html
└── docker-compose.yml                # Docker конфигурация
```

---

## 🐛 Troubleshooting

### Проблема: Docker контейнеры не запускаются

```bash
# Проверить логи
docker logs dvwa
docker logs zap

# Перезапустить
docker-compose down
docker-compose up -d
```

### Проблема: ZAP не может подключиться к DVWA

```bash
# На macOS/Windows используйте host.docker.internal
target = 'http://host.docker.internal:8080'

# На Linux используйте IP хоста
ip addr show docker0  # Посмотреть IP
target = 'http://172.17.0.1:8080'  # Используйте этот IP
```

### Проблема: Сканирование зависает

```bash
# Увеличьте timeout в скриптах
# Используйте меньший scope для тестов
# Проверьте что приложение доступно
curl http://localhost:8080  # Для DVWA
```

### Проблема: Недостаточно памяти

```bash
# Остановить ненужные контейнеры
docker stop $(docker ps -q)

# Выделить больше памяти Docker Desktop:
# Settings -> Resources -> Memory (увеличить до 4-8GB)
```

---

## 📚 Дополнительные ресурсы

- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [DVWA GitHub](https://github.com/digininja/DVWA)
- [WebGoat Project](https://owasp.org/www-project-webgoat/)
- [Juice Shop](https://owasp.org/www-project-juice-shop/)
- [Docker Documentation](https://docs.docker.com/)

---

## ✅ Checklist для запуска

- [ ] Docker установлен и запущен
- [ ] Python 3.8+ установлен
- [ ] Dependencies установлены (`pip install -r requirements.txt`)
- [ ] DVWA запущен (`docker-compose up -d dvwa`)
- [ ] ZAP запущен (`docker-compose up -d zap`)
- [ ] Сканирование выполнено
- [ ] Результаты проанализированы
- [ ] Отчёты созданы

**Готово к бенчмарк-тестированию!** 🎉
