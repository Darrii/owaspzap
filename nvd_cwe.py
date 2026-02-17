import requests
import json
import time
from collections import defaultdict
import numpy as np

def fetch_nvd_cves(results_per_page=2000, max_pages=10):
    """Скачивает CVE данные из NVD API"""
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    all_cves = []
    
    for page in range(max_pages):
        start_index = page * results_per_page
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        
        response = requests.get(base_url, params=params)
        if response.status_code != 200:
            print(f"Ошибка: {response.status_code}")
            break
            
        data = response.json()
        cves = data.get("vulnerabilities", [])
        all_cves.extend(cves)
        
        print(f"Загружено {len(all_cves)} CVE...")
        
        if len(cves) < results_per_page:
            break
            
        time.sleep(6)  # NVD rate limit: 5 req/30 sec без API ключа
    
    return all_cves

def extract_cwe_from_cve(cve_item):
    """Извлекает CWE типы из CVE записи"""
    cwes = []
    try:
        weaknesses = cve_item["cve"]["weaknesses"]
        for weakness in weaknesses:
            for desc in weakness["description"]:
                if desc["lang"] == "en":
                    cwes.append(desc["value"])  # например "CWE-89", "CWE-79"
    except (KeyError, TypeError):
        pass
    return cwes

def map_cwe_to_vuln_type(cwe_id):
    """Маппинг CWE → тип уязвимости для Марковской модели"""
    mapping = {
        "CWE-89":  "sql_injection",
        "CWE-79":  "xss",
        "CWE-22":  "path_traversal",
        "CWE-78":  "command_injection",
        "CWE-287": "auth_bypass",
        "CWE-200": "info_disclosure",
        "CWE-400": "dos",
        "CWE-502": "deserialization",
        "CWE-352": "csrf",
        "CWE-611": "xxe",
    }
    return mapping.get(cwe_id, "other")

def build_transition_matrix(cves_by_product):
    """
    Считает эмпирические частоты переходов.
    Логика: если продукт имеет уязвимости [A, B, C] по времени,
    то переходы: A→B, B→C (цепочка эксплуатации)
    """
    transition_counts = defaultdict(lambda: defaultdict(int))
    
    for product, vuln_sequence in cves_by_product.items():
        # Сортируем по дате публикации
        sorted_vulns = sorted(vuln_sequence, key=lambda x: x["date"])
        types = [v["type"] for v in sorted_vulns]
        
        # Считаем переходы
        for i in range(len(types) - 1):
            from_type = types[i]
            to_type = types[i + 1]
            transition_counts[from_type][to_type] += 1
    
    return transition_counts

def normalize_to_probability_matrix(transition_counts):
    """Преобразует counts → вероятности (MLE оценка)"""
    vuln_types = list(set(
        list(transition_counts.keys()) + 
        [t for counts in transition_counts.values() for t in counts.keys()]
    ))
    
    n = len(vuln_types)
    idx = {t: i for i, t in enumerate(vuln_types)}
    
    P = np.zeros((n, n))
    
    for from_type, counts in transition_counts.items():
        total = sum(counts.values())
        if total > 0:
            for to_type, count in counts.items():
                i, j = idx[from_type], idx[to_type]
                P[i][j] = count / total  # MLE: P(j|i) = count(i→j) / count(i)
    
    return P, vuln_types
def print_markov_results(P, vuln_types, transition_counts):
    """Выводит результаты в формате для статьи"""
    print("=" * 60)
    print("MARKOV CHAIN TRANSITION MATRIX (эмпирические P из NVD)")
    print("MLE оценка: P(j|i) = N(i→j) / N(i)")
    print("=" * 60)
    
    print(f"\n{'':20}", end="")
    for t in vuln_types:
        print(f"{t[:8]:10}", end="")
    print()
    
    for i, from_type in enumerate(vuln_types):
        print(f"{from_type[:20]:20}", end="")
        for j in range(len(vuln_types)):
            print(f"{P[i][j]:.4f}    ", end="")
        print()
    
    # Стационарное распределение (собственный вектор)
    eigenvalues, eigenvectors = np.linalg.eig(P.T)
    stationary_idx = np.argmax(np.abs(eigenvalues - 1) < 1e-6)
    stationary = np.real(eigenvectors[:, stationary_idx])
    stationary = stationary / stationary.sum()
    
    print("\nСтационарное распределение π:")
    for t, p in zip(vuln_types, stationary):
        print(f"  π({t}) = {p:.4f}")

    
def compare_with_expert_values(empirical_P, expert_P, vuln_types):
    """Сравниваем эмпирические vs экспертные вероятности"""
    diff = np.abs(empirical_P - expert_P)
    
    print("\nСравнение: Эмпирические (NVD) vs Экспертные")
    print(f"{'Переход':30} {'Эмпир.':10} {'Эксперт':10} {'|Δ|':10}")
    
    for i, from_t in enumerate(vuln_types):
        for j, to_t in enumerate(vuln_types):
            if expert_P[i][j] > 0 or empirical_P[i][j] > 0:
                print(f"{from_t}→{to_t:20} "
                      f"{empirical_P[i][j]:.4f}     "
                      f"{expert_P[i][j]:.4f}     "
                      f"{diff[i][j]:.4f}")
                

if __name__ == "__main__":
    # 1. Скачать данные
    print("Загружаем CVE из NVD...")
    cves = fetch_nvd_cves(max_pages=5)  # ~10k CVE
    print(f"Всего загружено: {len(cves)} CVE")

    # 2. Группировка по продукту + построение последовательностей
    cves_by_product = defaultdict(list)
    for item in cves:
        try:
            cve_data = item["cve"]
            cve_id = cve_data["id"]
            # Дата публикации
            date = cve_data.get("published", "1970-01-01")
            # CWE типы
            cwes = extract_cwe_from_cve(item)
            if not cwes:
                continue
            # Продукты из конфигураций
            products = set()
            configs = cve_data.get("configurations", [])
            for config in configs:
                for node in config.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        uri = cpe.get("criteria", "")
                        parts = uri.split(":")
                        if len(parts) >= 5:
                            products.add(f"{parts[3]}:{parts[4]}")
            if not products:
                products = {"unknown:" + cve_id[:8]}
            # Добавляем каждый CWE для каждого продукта
            for product in products:
                for cwe in cwes:
                    vuln_type = map_cwe_to_vuln_type(cwe)
                    cves_by_product[product].append({
                        "type": vuln_type,
                        "cwe": cwe,
                        "date": date,
                        "cve_id": cve_id
                    })
        except (KeyError, TypeError):
            continue

    print(f"Уникальных продуктов: {len(cves_by_product)}")

    # 3. Посчитать матрицу переходов
    transition_counts = build_transition_matrix(cves_by_product)
    P, vuln_types = normalize_to_probability_matrix(transition_counts)

    # 4. Вывести результаты
    print_markov_results(P, vuln_types, transition_counts)

    # 5. Сохранить для статьи
    np.save("empirical_transition_matrix.npy", P)
    with open("transition_matrix.json", "w") as f:
        json.dump({"types": vuln_types, "matrix": P.tolist()}, f, indent=2)
    print("\nСохранено: empirical_transition_matrix.npy и transition_matrix.json")