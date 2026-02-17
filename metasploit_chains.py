"""
Парсинг цепочек эксплуатации из Metasploit Framework.
Логика: exploit модуль (initial access) → post модуль (следующий шаг)
Извлекаем CWE/тип уязвимости из каждого модуля → строим переходы.
"""

import requests
import re
import time
import json
from collections import defaultdict

GITHUB_API = "https://api.github.com"
REPO = "rapid7/metasploit-framework"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# Маппинг ключевых слов в имени/пути модуля → тип уязвимости
KEYWORD_MAP = {
    "sql":          "sql_injection",
    "sqli":         "sql_injection",
    "xss":          "xss",
    "csrf":         "csrf",
    "traversal":    "path_traversal",
    "path_trav":    "path_traversal",
    "lfi":          "path_traversal",
    "rfi":          "path_traversal",
    "cmd":          "command_injection",
    "command":      "command_injection",
    "exec":         "command_injection",
    "rce":          "command_injection",
    "auth":         "auth_bypass",
    "bypass":       "auth_bypass",
    "login":        "auth_bypass",
    "deserial":     "deserialization",
    "marshal":      "deserialization",
    "ysoserial":    "deserialization",
    "info":         "info_disclosure",
    "disclosure":   "info_disclosure",
    "enum":         "info_disclosure",
    "gather":       "info_disclosure",
    "session":      "session_hijack",
    "fixation":     "session_hijack",
    "cookie":       "session_hijack",
    "upload":       "file_upload",
    "file_upload":  "file_upload",
    "xxe":          "xxe",
    "xml":          "xxe",
    "ssrf":         "ssrf",
    "csrf":         "csrf",
    "priv":         "privilege_escalation",
    "escalat":      "privilege_escalation",
    "local":        "privilege_escalation",
}

def get_module_list(module_type, max_modules=200):
    """Получает список модулей из GitHub API (рекурсивно)."""
    url = f"{GITHUB_API}/repos/{REPO}/git/trees/master?recursive=1"
    print(f"  Fetching tree from GitHub API...")
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code != 200:
        print(f"  GitHub API error: {resp.status_code} — {resp.json().get('message','')}")
        return []

    tree = resp.json().get("tree", [])
    modules = [
        item["path"] for item in tree
        if item["path"].startswith(f"modules/{module_type}/")
        and item["path"].endswith(".rb")
        and item["type"] == "blob"
    ]
    print(f"  Found {len(modules)} {module_type} modules")
    return modules[:max_modules]


def fetch_module_content(path):
    """Скачивает содержимое Ruby файла модуля."""
    url = f"https://raw.githubusercontent.com/{REPO}/master/{path}"
    resp = requests.get(url)
    if resp.status_code == 200:
        return resp.text
    return ""


def extract_cwe_from_module(content):
    """Извлекает CWE из References в модуле."""
    cwes = re.findall(r"'CWE',\s*'(\d+)'", content, re.IGNORECASE)
    return [f"CWE-{c}" for c in cwes]


def classify_module_by_path(path):
    """Классифицирует тип уязвимости по пути/имени модуля."""
    name = path.lower()
    for keyword, vuln_type in KEYWORD_MAP.items():
        if keyword in name:
            return vuln_type
    return "other"


def classify_module_by_content(content):
    """Классифицирует по содержимому — ищет CVE/CWE и ключевые слова."""
    content_lower = content.lower()
    for keyword, vuln_type in KEYWORD_MAP.items():
        if keyword in content_lower[:3000]:  # только первые 3000 символов (заголовок)
            return vuln_type
    return "other"


def build_exploit_post_chains(exploit_modules, post_modules):
    """
    Строит цепочки: exploit → post.
    Логика: каждый exploit даёт сессию, каждый post использует сессию.
    Пары строятся по категории: web exploit → info gathering post → privilege escalation post.
    """
    transitions = defaultdict(lambda: defaultdict(int))

    # Категоризируем все модули
    categorized_exploits = []
    for path, content in exploit_modules:
        vuln_type = classify_module_by_path(path)
        if vuln_type == "other":
            vuln_type = classify_module_by_content(content)
        categorized_exploits.append((path, vuln_type))

    categorized_posts = []
    for path, content in post_modules:
        vuln_type = classify_module_by_path(path)
        if vuln_type == "other":
            vuln_type = classify_module_by_content(content)
        categorized_posts.append((path, vuln_type))

    print(f"\n  Exploit modules categorized: {len(categorized_exploits)}")
    print(f"  Post modules categorized:    {len(categorized_posts)}")

    # Строим переходы: любой exploit → любой post (по типу)
    # Используем частоту совпадений типов как вес
    exploit_type_counts = defaultdict(int)
    post_type_counts = defaultdict(int)

    for _, t in categorized_exploits:
        exploit_type_counts[t] += 1
    for _, t in categorized_posts:
        post_type_counts[t] += 1

    print("\n  Exploit type distribution:")
    for t, c in sorted(exploit_type_counts.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c}")

    print("\n  Post module type distribution:")
    for t, c in sorted(post_type_counts.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c}")

    # Переходы: exploit_type → post_type (weighted by frequency)
    total_post = sum(post_type_counts.values())
    for exp_type in exploit_type_counts:
        for post_type, count in post_type_counts.items():
            transitions[exp_type][post_type] += count

    return transitions, categorized_exploits, categorized_posts


def normalize_transitions(transitions):
    """Нормализует counts → вероятности."""
    probabilities = {}
    for from_type, targets in transitions.items():
        total = sum(targets.values())
        if total > 0:
            probabilities[from_type] = {
                to_type: count / total
                for to_type, count in targets.items()
                if to_type != "other"
            }
    return probabilities


def print_results(probabilities):
    """Выводит матрицу переходов."""
    print("\n" + "=" * 70)
    print("METASPLOIT EXPLOIT CHAINS: Transition Probabilities")
    print("P(post_type | exploit_type) — из реальных модулей Metasploit")
    print("=" * 70)

    all_types = sorted(set(
        list(probabilities.keys()) +
        [t for v in probabilities.values() for t in v.keys()]
    ))

    # Убираем "other" из вывода
    display_types = [t for t in all_types if t != "other"]

    print(f"\n{'From \\ To':<25}", end="")
    for t in display_types:
        print(f"{t[:12]:<14}", end="")
    print()
    print("-" * (25 + 14 * len(display_types)))

    for from_type in display_types:
        if from_type not in probabilities:
            continue
        print(f"{from_type:<25}", end="")
        for to_type in display_types:
            p = probabilities[from_type].get(to_type, 0.0)
            print(f"{p:.4f}        ", end="")
        print()

    print("\n\nКлючевые переходы (P > 0.05):")
    print(f"{'Переход':<40} {'P(j|i)':>8}")
    print("-" * 50)
    for from_type in sorted(probabilities.keys()):
        for to_type, p in sorted(probabilities[from_type].items(),
                                  key=lambda x: -x[1]):
            if p > 0.05 and to_type != "other" and from_type != "other":
                print(f"  {from_type} → {to_type:<30} {p:.4f}")


if __name__ == "__main__":
    print("=== Metasploit Chain Analysis ===\n")

    # 1. Получить список модулей
    print("1. Получаем список exploit модулей...")
    exploit_paths = get_module_list("exploits", max_modules=150)
    time.sleep(1)

    print("2. Получаем список post модулей...")
    post_paths = get_module_list("post", max_modules=150)
    time.sleep(1)

    # 2. Скачать содержимое
    print(f"\n3. Скачиваем {len(exploit_paths)} exploit модулей...")
    exploit_modules = []
    for i, path in enumerate(exploit_paths):
        content = fetch_module_content(path)
        exploit_modules.append((path, content))
        if (i + 1) % 20 == 0:
            print(f"   {i + 1}/{len(exploit_paths)}...")
        time.sleep(0.1)

    print(f"4. Скачиваем {len(post_paths)} post модулей...")
    post_modules = []
    for i, path in enumerate(post_paths):
        content = fetch_module_content(path)
        post_modules.append((path, content))
        if (i + 1) % 20 == 0:
            print(f"   {i + 1}/{len(post_paths)}...")
        time.sleep(0.1)

    # 3. Строим цепочки
    print("\n5. Строим переходы...")
    transitions, cat_exploits, cat_posts = build_exploit_post_chains(
        exploit_modules, post_modules
    )

    # 4. Нормализуем
    probabilities = normalize_transitions(transitions)

    # 5. Выводим
    print_results(probabilities)

    # 6. Сохраняем
    with open("metasploit_transitions.json", "w") as f:
        json.dump(probabilities, f, indent=2)
    print("\n\nСохранено: metasploit_transitions.json")
