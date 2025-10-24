"""
Test script for PerformanceScanner
This script demonstrates how to use the PerformanceScanner class to perform
parallel and async scans, as well as benchmarking different scan profiles.
"""

import sys
import time
import logging
import asyncio
from PerformanceScanner import PerformanceScanner

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PerfTest')

async def run_async_test(scanner, target_url, profile_name):
    """
    Запуск асинхронного тестового сканирования.
    """
    logger.info(f"Запуск асинхронного тестирования для {target_url} с профилем {profile_name}")
    result = await scanner.async_scan(target_url, profile_name)
    return result

async def run_multiple_async_test(scanner, targets):
    """
    Запуск множественных асинхронных тестовых сканирований.
    """
    logger.info(f"Запуск множественных асинхронных тестирований для {len(targets)} целей")
    results = await scanner.run_multiple_async_scans(targets)
    return results

def run_parallel_test(scanner, targets, max_workers=2):
    """
    Запуск параллельных тестовых сканирований.
    """
    logger.info(f"Запуск параллельных тестирований для {len(targets)} целей")
    results = scanner.scan_multiple_targets(targets, max_workers)
    return results

def run_benchmark_test(scanner, target_url, profiles, iterations=1):
    """
    Запуск бенчмарка для сравнения профилей сканирования.
    """
    logger.info(f"Запуск бенчмарка для {target_url} с профилями {profiles}")
    results = scanner.benchmark_scan(target_url, profiles, iterations)
    return results

async def main_async():
    """
    Основная асинхронная функция тестирования PerformanceScanner.
    """
    if len(sys.argv) < 2:
        print("Использование: python test_performance.py <target_url> [test_type]")
        print("test_type: async, parallel, multiple, benchmark")
        sys.exit(1)
        
    target_url = sys.argv[1]
    test_type = "async" if len(sys.argv) < 3 else sys.argv[2]
    
    # Настройки подключения к ZAP
    zap_host = "localhost"
    zap_port = 8080
    zap_api_key = "12345"
    
    try:
        # Создание экземпляра PerformanceScanner
        logger.info("Инициализация PerformanceScanner...")
        scanner = PerformanceScanner(
            zap_api_key=zap_api_key,
            zap_host=zap_host,
            zap_port=zap_port
        )
        
        # Проверка соединения с ZAP
        if not scanner.check_connection():
            logger.error("Не удалось установить соединение с ZAP. Убедитесь, что ZAP запущен и доступен.")
            sys.exit(1)
            
        # Запуск выбранного типа теста
        if test_type == "async":
            # Асинхронное сканирование одной цели
            result = await run_async_test(scanner, target_url, "async_basic")
            print_result(result)
            
        elif test_type == "multiple":
            # Асинхронное сканирование нескольких целей
            targets = [
                {'url': target_url, 'profile': 'async_basic'},
                {'url': 'https://example.org', 'profile': 'async_basic'}
            ]
            results = await run_multiple_async_test(scanner, targets)
            print_multiple_results(results)
            
        elif test_type == "parallel":
            # Параллельное сканирование нескольких целей
            targets = [
                {'url': target_url, 'profile': 'standard'},
                {'url': 'https://example.org', 'profile': 'basic'}
            ]
            results = run_parallel_test(scanner, targets)
            print_multiple_results(results)
            
        elif test_type == "benchmark":
            # Бенчмарк сравнения профилей
            profiles = ['basic', 'standard', 'thorough']
            results = run_benchmark_test(scanner, target_url, profiles)
            print_benchmark_results(results)
            scanner.save_benchmark_results(results)
            
        else:
            logger.error(f"Неизвестный тип теста: {test_type}")
            print("Доступные типы тестов: async, parallel, multiple, benchmark")
            
    except Exception as e:
        logger.error(f"Ошибка при тестировании: {e}")
    finally:
        logger.info("Тестирование завершено")
        
def print_result(result):
    """
    Вывод информации о результате сканирования.
    """
    if result:
        print("\n" + "="*50)
        print(f"Результаты сканирования для {result['target_url']}")
        print(f"Профиль: {result['profile']['name']}")
        print(f"Время сканирования: {result['scan_time']:.2f} секунд")
        print(f"Количество предупреждений: {result['alerts_count']}")
        print("="*50 + "\n")
    else:
        print("Ошибка: Нет результатов сканирования")

def print_multiple_results(results):
    """
    Вывод информации о результатах множественных сканирований.
    """
    if results:
        print("\n" + "="*50)
        print(f"Результаты множественных сканирований")
        print("-"*50)
        
        for i, result in enumerate(results):
            if isinstance(result, dict) and 'target_url' in result:
                print(f"Сканирование #{i+1}: {result['target_url']}")
                print(f"Профиль: {result['profile']['name']}")
                print(f"Время: {result['scan_time']:.2f} секунд")
                print(f"Предупреждения: {result['alerts_count']}")
                print("-"*30)
            else:
                print(f"Сканирование #{i+1}: Ошибка или неполные данные")
                print("-"*30)
                
        print("="*50 + "\n")
    else:
        print("Ошибка: Нет результатов множественных сканирований")

def print_benchmark_results(results):
    """
    Вывод информации о результатах бенчмарка.
    """
    if not results or 'profiles' not in results:
        print("Ошибка: Нет результатов бенчмарка")
        return
        
    print("\n" + "="*50)
    print(f"Результаты бенчмарка для {results['target_url']}")
    print("-"*50)
    
    for profile, data in results['profiles'].items():
        print(f"Профиль: {profile}")
        print(f"Среднее время: {data['avg_time']:.2f} секунд")
        print(f"Среднее кол-во предупреждений: {data['avg_alerts']:.1f}")
        print("-"*30)
    
    print("\nСравнение профилей:")
    comparison = results['comparison']
    print(f"Самый быстрый: {comparison['fastest_profile']} ({comparison['fastest_time']:.2f} секунд)")
    print(f"Самый тщательный: {comparison['most_thorough_profile']} ({comparison['most_alerts']:.1f} предупреждений)")
    print(f"Лучшее соотношение: {comparison['best_performance_ratio']}")
    print("="*50 + "\n")

def main():
    """
    Точка входа для запуска асинхронной функции main_async.
    """
    asyncio.run(main_async())

if __name__ == "__main__":
    main()