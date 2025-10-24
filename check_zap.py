"""
Simple script to check ZAP API connectivity
"""

import sys
import logging
from zapv2 import ZAPv2

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ZAPCheck')

def main():
    """
    Функция для проверки подключения к ZAP API
    """
    # Настройки подключения к ZAP
    zap_host = "localhost"  # или IP Docker-контейнера
    zap_port = 8080
    zap_api_key = "12345"
    zap_url = f'http://{zap_host}:{zap_port}'
    
    logger.info(f"Проверка подключения к ZAP API по адресу: {zap_url}")
    
    try:
        # Попытка подключения к ZAP API
        zap = ZAPv2(apikey=zap_api_key, proxies={'http': zap_url, 'https': zap_url})
        
        # Получение версии ZAP
        version = zap.core.version
        
        # Вывод результата
        print("\n" + "="*50)
        print(f"Соединение с ZAP установлено успешно!")
        print(f"Версия ZAP: {version}")
        print("="*50 + "\n")
        
        # Получение списка сканов (если есть)
        try:
            scans = zap.ascan.scans
            print(f"Активные сканирования: {scans}")
        except Exception as e:
            print(f"Информация о сканированиях: Не удалось получить ({e})")
        
        # Проверка статуса ZAP - используем более стабильный метод
        try:
            sites = zap.core.sites
            print(f"Известные сайты: {sites}")
            
            # Получаем список плагинов
            plugins = zap.pscan.scanners
            print(f"Количество плагинов пассивного сканирования: {len(plugins)}")
        except Exception as e:
            print(f"Дополнительная информация недоступна: {e}")
            
        
    except Exception as e:
        print("\n" + "="*50)
        print(f"ОШИБКА: Не удалось подключиться к ZAP API")
        print(f"Причина: {e}")
        print("\nПроверьте:")
        print("1. Запущен ли контейнер ZAP (docker ps)")
        print("2. Правильно ли указаны host и port")
        print("3. Правильно ли указан API ключ")
        print("="*50 + "\n")
        
if __name__ == "__main__":
    main()