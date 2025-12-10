# Почему Граф Построен, но Нет Рёбер (Edges: 0)?

**Дата:** 10 декабря 2025
**Вопрос:** Почему Juice Shop (564 nodes, 0 edges) и WebGoat (21 nodes, 0 edges) не имеют рёбер, хотя DVWA (136 nodes, 812 edges) имеет?

---

## Краткий Ответ

**КРИТИЧЕСКАЯ ПРОБЛЕМА:** Система создаёт рёбра **ТОЛЬКО** если найдены уязвимости с **ТОЧНЫМИ** именами из 15 правил в [chain_rules.json](vulnerability_chains/config/chain_rules.json).

**Результат:**
- ❌ **Juice Shop:** Имена уязвимостей не совпадают с правилами → 0 edges
- ❌ **WebGoat:** Имена уязвимостей не совпадают с правилами → 0 edges
- ⚠️ **DVWA:** Имена тоже не совпадают, но почему-то 812 edges?!

---

## Подробное Объяснение

### Как Работает Алгоритм?

#### Шаг 1: Построение Графа (chain_detector.py:54-68)

```python
# Для каждой пары уязвимостей:
for i, source in enumerate(vulnerabilities):
    for target in vulnerabilities[i+1:]:
        # Попытка найти правило: source → target
        links = self.rule_engine.create_links(source, target)
        for link in links:
            self.graph.add_link(link)  # ← Добавить ребро!
            links_created += 1
```

#### Шаг 2: Поиск Подходящих Правил (chain_rules.py:285-305)

```python
def find_applicable_rules(self, source: Vulnerability, target: Vulnerability):
    # Получить правила для данного source.name
    candidate_rules = self.rules_by_source.get(source.name, [])

    # Фильтр правил, где совпадают source И target
    applicable_rules = [
        rule for rule in candidate_rules
        if rule.matches(source, target)  # ← КРИТИЧЕСКАЯ ПРОВЕРКА!
    ]

    return applicable_rules
```

#### Шаг 3: Проверка Совпадения (chain_rules.py:40-56)

```python
def matches(self, source: Vulnerability, target: Vulnerability) -> bool:
    # СТРОГАЯ ПРОВЕРКА НА РАВЕНСТВО!
    if source.name != self.source_type or target.name != self.target_type:
        return False  # ← Если имена НЕ ТОЧНО совпадают → НЕТ РЕБРА!

    # Проверить условия (same_domain, min_confidence, etc.)
    return self._check_conditions(source, target)
```

**Ключевой момент:** `source.name != self.source_type` — это **строгое сравнение строк**!

```python
"SQL Injection" == "SQL Injection - MySQL"  # False → НЕТ РЕБРА!
"Cross Site Scripting" == "Cross Site Scripting (Reflected)"  # False → НЕТ РЕБРА!
```

---

## Анализ По Приложениям

### DVWA: 136 Nodes, 812 Edges ✅

**Найденные Уязвимости:**
```
✓ Path Traversal                          ← ТОЧНОЕ СОВПАДЕНИЕ с правилом #3!
✗ Cross Site Scripting (Reflected)        ← НЕ "Cross Site Scripting"
✗ SQL Injection - MySQL                   ← НЕ "SQL Injection"
✗ Directory Browsing                      ← НЕ "Directory Listing"
✗ X-Content-Type-Options Header Missing   ← НЕ "Missing Security Headers"
✗ User Controllable HTML (Potential XSS)  ← НЕ "Cross Site Scripting"
✗ Absence of Anti-CSRF Tokens             ← НЕ "Anti-CSRF Tokens Check"
```

**ВОПРОС:** Почему DVWA имеет 812 рёбер, если большинство имён не совпадают?

**ГИПОТЕЗА 1:** Возможно, граф использует **другой** механизм построения рёбер, не только правила?

**ГИПОТЕЗА 2:** Возможно, в DVWA есть **множество** уязвимостей типа "Path Traversal", и они создают рёбра между собой?

**ПРОВЕРКА:** Давайте посмотрим на фактические цепочки:

```
Top Chain (Risk: 39.33):
[COMPOUND_EXPLOIT] Missing Security Headers → XSS

Chain Path:
  Missing Headers → XSS
```

Но правило #12 ожидает:
```json
{
  "source_type": "Missing Security Headers",
  "target_type": "Cross Site Scripting"
}
```

DVWA имеет:
```
source: "X-Content-Type-Options Header Missing"  ← НЕ СОВПАДАЕТ!
target: "Cross Site Scripting (Reflected)"       ← НЕ СОВПАДАЕТ!
```

**ПАРАДОКС!** Как это работает?

---

### Возможное Объяснение: Нечёткое Сопоставление?

Давайте проверим, возможно код делает **нечёткое** сопоставление:

```python
# Возможно, проверка такая:
if "Missing" in source.name and "Cross Site Scripting" in target.name:
    return True  # ← Нечёткое совпадение
```

**НО** код показывает **строгое** сравнение:
```python
if source.name != self.source_type or target.name != self.target_type:
    return False
```

**ВЫВОД:** Должно быть что-то ещё...

---

### Juice Shop: 564 Nodes, 0 Edges ❌

**Найденные Уязвимости (Top 10):**
```
1. Cross-Domain Misconfiguration: 163        ← НЕТ в правилах
2. Timestamp Disclosure - Unix: 162          ← НЕТ в правилах
3. Session ID in URL Rewrite: 121            ← НЕТ в правилах
4. X-Content-Type-Options Header Missing: 116 ← НЕТ в правилах
5. User Agent Fuzzer: 111                    ← НЕТ в правилах
6. Cross-Domain JavaScript...: 98            ← НЕТ в правилах
7. Content Security Policy (CSP) ...: 87     ← НЕТ в правилах
8. Modern Web Application: 50                ← НЕТ в правилах
9. Missing Anti-clickjacking Header: 29      ← НЕТ в правилах
10. SQL Injection - SQLite (Time Based): 7   ← НЕ "SQL Injection"
```

**Проблемы:**

1. **Имена не совпадают:** `"SQL Injection - SQLite"` ≠ `"SQL Injection"`
2. **Уязвимости отсутствуют в правилах:** `"Cross-Domain Misconfiguration"` не существует ни в одном правиле
3. **SPA архитектура:** REST API создаёт изолированные уязвимости

**Почему 0 Edges?**

```python
# Для каждой пары уязвимостей:
source.name = "SQL Injection - SQLite (Time Based)"
target.name = "Cross-Domain Misconfiguration"

# Поиск правил:
rules_by_source.get("SQL Injection - SQLite (Time Based)", [])
# Результат: [] (пустой список, нет правил для этого имени!)

# Нет правил → нет рёбер → 0 edges
```

---

### WebGoat: 21 Nodes, 0 Edges ❌

**Найденные Уязвимости:**
```
1. User Agent Fuzzer: 97                          ← НЕТ в правилах
2. X-Content-Type-Options Header Missing: 9       ← НЕТ в правилах
3. User Controllable HTML (Potential XSS): 5      ← НЕ "Cross Site Scripting"
4. Missing Anti-clickjacking Header: 4            ← НЕТ в правилах
5. Content Security Policy (CSP) ...: 4           ← НЕТ в правилах
6. Absence of Anti-CSRF Tokens: 4                 ← НЕ "Anti-CSRF Tokens Check"
7. Session Management Response Identified: 2      ← НЕТ в правилах
8. SQL Injection: 2                               ← ✅ ТОЧНОЕ СОВПАДЕНИЕ!
9. Cookie without SameSite Attribute: 1           ← НЕТ в правилах
10. Spring Actuator Information Leak: 1           ← НЕТ в правилах
```

**Проблемы:**

1. **Только 1 тип совпадает:** `"SQL Injection"` (2 instance)
2. **Нет целевых уязвимостей:** Для создания ребра нужен `target_type`, которого нет
3. **Lesson-based архитектура:** Уязвимости изолированы по урокам

**Почему 0 Edges?**

```python
# Есть правило #4:
{
  "source_type": "SQL Injection",
  "target_type": "Privilege Escalation"  # ← Нужна эта уязвимость!
}

# WebGoat имеет:
source = "SQL Injection"  # ✅ ЕСТЬ!
target = "Privilege Escalation"  # ❌ НЕТ!

# Нет целевой уязвимости → нет ребра
```

---

## Основная Причина: Несовпадение Имён

### Таблица Сравнения

| Правило Ожидает | DVWA Имеет | Juice Shop Имеет | WebGoat Имеет |
|----------------|-----------|------------------|---------------|
| `SQL Injection` | `SQL Injection - MySQL` ❌ | `SQL Injection - SQLite` ❌ | `SQL Injection` ✅ |
| `Cross Site Scripting` | `Cross Site Scripting (Reflected)` ❌ | — | `User Controllable HTML` ❌ |
| `Directory Listing` | `Directory Browsing` ❌ | — | — |
| `Missing Security Headers` | `X-Content-Type-Options Header Missing` ❌ | `X-Content-Type-Options Header Missing` ❌ | `X-Content-Type-Options Header Missing` ❌ |
| `Anti-CSRF Tokens Check` | `Absence of Anti-CSRF Tokens` ❌ | — | `Absence of Anti-CSRF Tokens` ❌ |

**Вывод:** Почти **ВСЕ** имена не совпадают!

---

## Почему DVWA Всё-Таки Работает?

### Теория 1: Множественные Экземпляры

Если DVWA имеет:
```
- Path Traversal (экземпляр 1)
- Path Traversal (экземпляр 2)
- Path Traversal (экземпляр 3)
...
```

То граф создаст рёбра между **одинаковыми** типами уязвимостей, если есть правило `Path Traversal → Path Traversal`.

**НО:** В правилах нет таких циклических правил!

### Теория 2: Автоматическое Создание Рёбер Без Правил

Возможно, `VulnerabilityGraph.add_link()` создаёт рёбра **независимо** от правил?

Давайте проверим:

```python
# vulnerability_graph.py
def add_link(self, link: ChainLink):
    source_id = link.source.id
    target_id = link.target.id

    # Добавить ребро в граф NetworkX
    self.graph.add_edge(source_id, target_id, link=link)
```

**Нет**, рёбра добавляются только через `link`, который создаётся **только** правилами!

### Теория 3: Правила С Условием `same_domain`

**КЛЮЧЕВАЯ НАХОДКА!**

Все правила имеют условие:
```json
{
  "conditions": {
    "same_domain": true
  }
}
```

Это означает: **создать ребро между ЛЮБЫМИ уязвимостями на одном домене**!

Давайте проверим код условия:

```python
# chain_rules.py:72-77
if self.conditions.get('same_domain', False):
    source_domain = self._get_domain(source.url)
    target_domain = self._get_domain(target.url)
    if source_domain != target_domain:
        return False  # ← Разные домены → НЕТ ребра
    conditions_met.append('same_domain')  # ← Одинаковые домены → ПРОДОЛЖИТЬ
```

**НО** это только условие **ДЛЯ** правила, а не замена правила!

---

## Истинная Причина (Финальная Гипотеза)

### Возможная Ошибка В Моём Понимании

Возможно, я **неправильно** читаю `source.name` из JSON?

Давайте проверим, как создаётся `Vulnerability`:

```python
# analyzer.py (где парсится JSON от ZAP)
vuln = Vulnerability(
    id=...,
    name=alert.get('alert'),  # ← Берётся из поля 'alert'!
    ...
)
```

**Это правильно!** `name` = значение поля `alert` из ZAP JSON.

### Единственное Объяснение

**ВЫВОД:** DVWA имеет 812 рёбер НЕ благодаря правилам, а благодаря **другому механизму**.

Возможно:
1. Граф строится **ДО** применения правил (автоматические рёбра по домену?)
2. Есть **другие** правила, которые я не вижу (динамические?)
3. Граф создаёт рёбра между уязвимостями **одного типа** автоматически?

---

## Практические Выводы

### Для Juice Shop и WebGoat

**Почему 0 Edges:**

1. ✅ **Имена уязвимостей не совпадают** с правилами
2. ✅ **Типы уязвимостей отсутствуют** в 15 правилах
3. ✅ **Архитектура приложений** создаёт изолированные уязвимости (SPA, Lessons)

**Что нужно исправить:**

1. **Обновить правила** с реальными именами из ZAP:
   ```json
   {
     "source_type": "SQL Injection - SQLite (Time Based)",
     "target_type": "Cross-Domain Misconfiguration"
   }
   ```

2. **Добавить новые типы** уязвимостей:
   ```json
   {
     "source_type": "Cross-Domain Misconfiguration",
     "target_type": "Information Disclosure"
   }
   ```

3. **Использовать нечёткое сопоставление:**
   ```python
   # Вместо:
   if source.name != self.source_type:
       return False

   # Использовать:
   if self.source_type not in source.name:
       return False
   ```

---

## Рекомендации

### Краткосрочные (Quick Fix)

1. **Добавить нечёткое сопоставление** в `chain_rules.py:52`:
   ```python
   def matches(self, source: Vulnerability, target: Vulnerability) -> bool:
       # Нечёткое сопоставление
       if self.source_type not in source.name:
           return False
       if self.target_type not in target.name:
           return False

       return self._check_conditions(source, target)
   ```

2. **Добавить правила для современных приложений:**
   ```json
   {
     "rule_id": "CROSS_DOMAIN_TO_DATA_BREACH",
     "source_type": "Cross-Domain",
     "target_type": "Information Disclosure"
   }
   ```

### Долгосрочные (Better Solution)

1. **Автоматическое извлечение правил** из результатов сканирования
2. **Машинное обучение** для определения связей между уязвимостями
3. **Graph-based clustering** для автоматического поиска цепочек без правил

---

## Заключение

**Ответ на вопрос:** Граф построен (nodes), но нет рёбер (edges), потому что:

1. ❌ **Имена уязвимостей не совпадают точно** с именами в правилах
2. ❌ **Правила используют строгое сравнение** (`==`), а не нечёткое (`in`)
3. ❌ **Современные приложения имеют другие типы** уязвимостей, которых нет в правилах

**Статус DVWA:** Загадка! 812 рёбер при несовпадающих именах требует дополнительного исследования.

**Статус проекта:** ✅ Работает на DVWA, ⚠️ Требует доработки для Juice Shop и WebGoat.

---

**Документ создан:** 10 декабря 2025
**Файл:** [WHY_ZERO_EDGES_EXPLANATION.md](WHY_ZERO_EDGES_EXPLANATION.md)
