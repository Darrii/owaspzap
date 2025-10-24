"""
Test script for EnhancedScanner
This script demonstrates how to use the EnhancedScanner class to perform
a basic scan against a target URL.
"""

import sys
import time
import logging
from EnhancedScanner import EnhancedScanner

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ZAPTest')

def main():
    """
    Основная функция тестирования EnhancedScanner.
    """
    if len(sys.argv) < 2:
        print("Использование: python test_scanner.py <target_url> [profile_name]")
        print("Доступные профили: basic, standard, thorough, e-commerce")
        sys.exit(1)
        
    target_url = sys.argv[1]
    profile = "basic" if len(sys.argv) < 3 else sys.argv[2]
    
    # Настройки подключения к ZAP
    zap_host = "localhost"  # или IP Docker-контейнера
    zap_port = 8080
    zap_api_key = "12345"
    
    try:
        # Создание экземпляра EnhancedScanner
        logger.info("Инициализация EnhancedScanner...")
        scanner = EnhancedScanner(
            zap_api_key=zap_api_key,
            zap_host=zap_host,
            zap_port=zap_port
        )
        
        # Проверка соединения с ZAP
        if not scanner.check_connection():
            logger.error("Не удалось установить соединение с ZAP. Убедитесь, что ZAP запущен и доступен.")
            sys.exit(1)
            
        # Запуск сканирования
        logger.info(f"Запуск сканирования {target_url} с профилем '{profile}'...")
        result = scanner.start_scan(target_url, profile)
        
        if result:
            # Вывод краткой информации о результатах
            print("\n" + "="*50)
            print(f"Результаты сканирования для {target_url}")
            print(f"Профиль: {result['profile']['name']}")
            print(f"Время сканирования: {result['scan_time']:.2f} секунд")
            print(f"Количество предупреждений: {result['alerts_count']}")
            print("="*50 + "\n")
            
            # Сохранение отчетов в разных форматах
            scanner.save_report(result, 'json')
            scanner.save_report(result, 'html')
            scanner.save_report(result, 'xml')
            
            # Преобразование результатов в DataFrame для анализа
            df = scanner.get_scan_results_dataframe(result)
            if not df.empty:
                print("Топ-5 предупреждений по риску:")
                print(df.sort_values(by='risk', ascending=False).head(5)[['name', 'risk', 'url']])
            
        else:
            logger.error("Сканирование не вернуло результатов")
            
    except Exception as e:
        logger.error(f"Ошибка при тестировании: {e}")
    finally:
        # Завершение работы ZAP (опционально)
        # scanner.shutdown()
        logger.info("Тестирование завершено")
        
if __name__ == "__main__":
    main()