"""
Test script for IntelligentAnalyzer
This script demonstrates how to use the IntelligentAnalyzer class to analyze scan results,
reduce false positives, and generate remediation guides.
"""

import sys
import json
import logging
import os
import pandas as pd
from EnhancedScanner import EnhancedScanner
from IntelligentAnalyzer import IntelligentAnalyzer

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('AnalyzerTest')

# Путь для сохранения и загрузки модели
MODEL_PATH = "intelligent_analyzer_model.pkl"

# Путь для сохранения и загрузки тестовых данных
SAMPLE_DATA_PATH = "sample_data.json"

def create_sample_data():
    """
    Создание примера данных для тестирования.
    """
    sample_alerts = [
        {
            "name": "Cross Site Scripting (Reflected)",
            "risk": "High",
            "confidence": "Medium",
            "url": "https://example.com/search?q=test",
            "param": "q",
            "description": "Отраженный XSS (Cross-Site Scripting) позволяет атакующему внедрить исполняемый JavaScript код.",
            "solution": "Правильно экранируйте все ненадежные данные перед размещением на странице.",
            "reference": "https://owasp.org/www-community/attacks/xss/",
            "evidence": "<script>alert(1);</script>"
        },
        {
            "name": "SQL Injection",
            "risk": "High",
            "confidence": "High",
            "url": "https://example.com/product?id=1",
            "param": "id",
            "description": "SQL-инъекция позволяет атакующему внедрять или изменять SQL-запросы.",
            "solution": "Используйте подготовленные выражения (prepared statements) или хранимые процедуры.",
            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
            "evidence": "1' OR '1'='1"
        },
        {
            "name": "X-Content-Type-Options Header Missing",
            "risk": "Low",
            "confidence": "Medium",
            "url": "https://example.com/style.css",
            "param": "",
            "description": "Отсутствие заголовка X-Content-Type-Options может позволить браузерам интерпретировать файлы как разные MIME-типы.",
            "solution": "Добавьте заголовок X-Content-Type-Options: nosniff для всех ответов.",
            "reference": "https://owasp.org/www-project-secure-headers/",
            "evidence": ""
        },
        {
            "name": "Cookie No HttpOnly Flag",
            "risk": "Low",
            "confidence": "Medium",
            "url": "https://example.com",
            "param": "session",
            "description": "Cookies, используемые для аутентификации, не имеют флага HttpOnly, что может привести к краже cookie через XSS.",
            "solution": "Установите флаг HttpOnly для всех cookies, содержащих чувствительные данные.",
            "reference": "https://owasp.org/www-community/HttpOnly",
            "evidence": "Set-Cookie: session=123; Path=/"
        },
        {
            "name": "X-Frame-Options Header Not Set",
            "risk": "Medium",
            "confidence": "Medium",
            "url": "https://example.com",
            "param": "",
            "description": "Отсутствие заголовка X-Frame-Options позволяет встраивать страницу в iframe, что может привести к clickjacking атакам.",
            "solution": "Все страницы, содержащие чувствительные данные, должны включать заголовок X-Frame-Options.",
            "reference": "https://owasp.org/www-community/attacks/Clickjacking",
            "evidence": ""
        }
    ]
    
    sample_scan_result = {
        "target_url": "https://example.com",
        "profile": {
            "name": "Стандартное сканирование",
            "description": "Полное сканирование с активным тестированием"
        },
        "scan_time": 120.5,
        "alerts": sample_alerts,
        "alerts_count": len(sample_alerts),
        "scan_date": "2025-05-18 12:30:45"
    }
    
    # Пример размеченных данных для обучения
    labeled_data = [
        {"alert": "X-Content-Type-Options Header Missing", "url": "https://example.com/style.css", "is_false_positive": True},
        {"alert": "Cross Site Scripting (Reflected)", "url": "https://example.com/search?q=test", "is_false_positive": False},
        {"alert": "SQL Injection", "url": "https://example.com/product?id=1", "is_false_positive": False},
        {"alert": "Cookie No HttpOnly Flag", "url": "https://example.com", "is_false_positive": False},
        {"alert": "X-Frame-Options Header Not Set", "url": "https://example.com", "is_false_positive": False}
    ]
    
    sample_data = {
        "scan_result": sample_scan_result,
        "labeled_data": labeled_data
    }
    
    # Сохранение в файл
    with open(SAMPLE_DATA_PATH, 'w', encoding='utf-8') as f:
        json.dump(sample_data, f, ensure_ascii=False, indent=4)
    
    logger.info(f"Примеры данных созданы и сохранены в {SAMPLE_DATA_PATH}")
    
    return sample_data

def load_sample_data():
    """
    Загрузка примера данных для тестирования.
    """
    if not os.path.exists(SAMPLE_DATA_PATH):
        return create_sample_data()
    
    try:
        with open(SAMPLE_DATA_PATH, 'r', encoding='utf-8') as f:
            sample_data = json.load(f)
        
        logger.info(f"Примеры данных загружены из {SAMPLE_DATA_PATH}")
        return sample_data
    except Exception as e:
        logger.error(f"Ошибка при загрузке примеров данных: {e}")
        return create_sample_data()

def train_model_test(analyzer, sample_data):
    """
    Тестирование обучения модели.
    """
    logger.info("Тестирование обучения модели...")
    
    # Получение данных
    scan_result = sample_data["scan_result"]
    labeled_data = sample_data["labeled_data"]
    
    # Создание обучающего датасета
    training_df = analyzer.create_training_dataset([scan_result], labeled_data)
    
    # Обучение модели
    analyzer.train_model(training_df, MODEL_PATH)
    
    logger.info("Тестирование обучения модели завершено")

def analyze_results_test(analyzer, sample_data):
    """
    Тестирование анализа результатов сканирования.
    """
    logger.info("Тестирование анализа результатов сканирования...")
    
    # Получение данных
    scan_result = sample_data["scan_result"]
    
    # Анализ результатов
    analyzed_results = analyzer.analyze_scan_results(scan_result)
    
    # Вывод результатов
    print("\n" + "="*50)
    print("Результаты анализа:")
    print(f"Исходное кол-во оповещений: {analyzed_results['analysis_metrics']['original_count']}")
    print(f"Отфильтровано: {analyzed_results['analysis_metrics']['original_count'] - analyzed_results['analysis_metrics']['filtered_count']}")
    print(f"Итоговое кол-во оповещений: {analyzed_results['analysis_metrics']['final_count']}")
    print(f"Процент сокращения: {analyzed_results['analysis_metrics']['reduction_percentage']:.2f}%")
    print("="*50 + "\n")
    
    logger.info("Тестирование анализа результатов завершено")
    
    return analyzed_results

def remediation_guide_test(analyzer, analyzed_results):
    """
    Тестирование создания руководства по устранению уязвимостей.
    """
    logger.info("Тестирование создания руководства по устранению уязвимостей...")
    
    # Получение оповещений
    alerts = analyzed_results['alerts']
    
    # Создание руководства
    remediation_guide = analyzer.generate_remediation_guide(alerts)
    
    # Вывод руководства
    print("\n" + "="*50)
    print("Руководство по устранению уязвимостей:")
    
    for category, vulns in remediation_guide.items():
        if vulns:
            print(f"\n{category.upper()} ({len(vulns)}):")
            for i, vuln in enumerate(vulns, 1):
                print(f"  {i}. {vuln['alert_name']} ({vuln['risk']}) - {vuln['instance_count']} экземпляр(ов)")
                print(f"     Решение: {vuln['solution'][:100]}...")
    
    print("="*50 + "\n")
    
    logger.info("Тестирование создания руководства завершено")

def full_analysis_test(analyzer, sample_data):
    """
    Тестирование полного анализа и резюмирования.
    """
    logger.info("Тестирование полного анализа и резюмирования...")
    
    # Получение данных
    scan_result = sample_data["scan_result"]
    
    # Полный анализ
    full_analysis = analyzer.analyze_and_summarize(scan_result)
    
    # Вывод результатов
    print("\n" + "="*50)
    print("Полный анализ результатов сканирования:")
    print(f"Целевой URL: {full_analysis['summary']['target_url']}")
    print(f"Дата сканирования: {full_analysis['summary']['scan_date']}")
    print(f"Время сканирования: {full_analysis['summary']['scan_time']:.2f} секунд")
    print(f"Всего оповещений: {full_analysis['summary']['total_alerts']}")
    print(f"После анализа: {full_analysis['summary']['analyzed_alerts']}")
    print(f"Сокращение ложных срабатываний: {full_analysis['summary']['false_positives_reduction']:.2f}%")
    
    print("\nРаспределение рисков:")
    print(f"Критичных: {full_analysis['summary']['risk_summary']['critical']}")
    print(f"Высоких: {full_analysis['summary']['risk_summary']['high']}")
    print(f"Средних: {full_analysis['summary']['risk_summary']['medium']}")
    print(f"Низких: {full_analysis['summary']['risk_summary']['low']}")
    
    print("\nТоп уязвимости:")
    for i, vuln in enumerate(full_analysis['summary']['top_vulnerabilities'], 1):
        print(f"  {i}. {vuln['name']} ({vuln['risk']}) - CVSS: {vuln['cvss_base_score']}")
    
    print("="*50 + "\n")
    
    logger.info("Тестирование полного анализа завершено")
    
    # Сохранение результатов анализа в файл
    with open("full_analysis_result.json", 'w', encoding='utf-8') as f:
        json.dump(full_analysis, f, ensure_ascii=False, indent=4)
    
    logger.info("Результаты полного анализа сохранены в full_analysis_result.json")

def perform_live_scan_and_analyze(target_url):
    """
    Выполнение реального сканирования и анализ результатов.
    """
    logger.info(f"Запуск сканирования для {target_url} и последующий анализ...")
    
    try:
        # Настройки подключения к ZAP
        zap_host = "localhost"
        zap_port = 8080
        zap_api_key = "12345"
        
        # Создание сканера
        scanner = EnhancedScanner(
            zap_api_key=zap_api_key,
            zap_host=zap_host,
            zap_port=zap_port
        )
        
        # Проверка соединения с ZAP
        if not scanner.check_connection():
            logger.error("Не удалось установить соединение с ZAP. Убедитесь, что ZAP запущен и доступен.")
            return None
        
        # Запуск сканирования
        scan_result = scanner.start_scan(target_url, "thorough")
        
        if not scan_result:
            logger.error("Сканирование не вернуло результатов")
            return None
        
        # Создание анализатора
        analyzer = IntelligentAnalyzer(MODEL_PATH)
        
        # Загрузка модели, если существует
        if os.path.exists(MODEL_PATH):
            analyzer.load_model(MODEL_PATH)
        
        # Полный анализ результатов
        analyzed_results = analyzer.analyze_and_summarize(scan_result)
        
        # Сохранение результатов
        output_file = f"scan_analysis_{target_url.replace('https://', '').replace('http://', '').replace('/', '_')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analyzed_results, f, ensure_ascii=False, indent=4)
        
        logger.info(f"Сканирование и анализ завершены. Результаты сохранены в {output_file}")
        
        return analyzed_results
    
    except Exception as e:
        logger.error(f"Ошибка при сканировании и анализе: {e}")
        return None

def main():
    """
    Основная функция для тестирования IntelligentAnalyzer.
    """
    if len(sys.argv) < 2:
        print("Использование: python test_analyzer.py <test_type> [target_url]")
        print("test_type: train, analyze, remediation, full, live")
        print("target_url: URL для сканирования (только для live)")
        sys.exit(1)
    
    test_type = sys.argv[1]
    target_url = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        # Загрузка или создание примера данных
        sample_data = load_sample_data()
        
        # Создание анализатора
        analyzer = IntelligentAnalyzer(MODEL_PATH if os.path.exists(MODEL_PATH) else None)
        
        if test_type == "train":
            # Тестирование обучения модели
            train_model_test(analyzer, sample_data)
            
        elif test_type == "analyze":
            # Тестирование анализа результатов
            analyze_results_test(analyzer, sample_data)
            
        elif test_type == "remediation":
            # Тестирование создания руководства
            analyzed_results = analyze_results_test(analyzer, sample_data)
            remediation_guide_test(analyzer, analyzed_results)
            
        elif test_type == "full":
            # Тестирование полного анализа
            full_analysis_test(analyzer, sample_data)
            
        elif test_type == "live":
            # Реальное сканирование и анализ
            if not target_url:
                logger.error("Не указан целевой URL для сканирования")
                print("Использование: python test_analyzer.py live <target_url>")
                sys.exit(1)
            
            perform_live_scan_and_analyze(target_url)
            
        else:
            logger.error(f"Неизвестный тип теста: {test_type}")
            print("Доступные типы тестов: train, analyze, remediation, full, live")
            
    except Exception as e:
        logger.error(f"Ошибка при тестировании: {e}")
    finally:
        logger.info("Тестирование завершено")

if __name__ == "__main__":
    main()