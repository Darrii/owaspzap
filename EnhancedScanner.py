"""
EnhancedScanner - Улучшенная обертка для OWASP ZAP API
Этот модуль предоставляет расширенные возможности для работы с OWASP ZAP API,
включая различные профили сканирования и улучшенный анализ результатов.
"""

import time
import json
import logging
from zapv2 import ZAPv2
import pandas as pd

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('EnhancedScanner')

class EnhancedScanner:
    """
    Класс, предоставляющий расширенные возможности для работы с OWASP ZAP.
    """
    def __init__(self, zap_api_key='12345', zap_host='localhost', zap_port=8080):
        """
        Инициализация EnhancedScanner.
        
        Args:
            zap_api_key (str): Ключ API для ZAP
            zap_host (str): Хост, на котором запущен ZAP
            zap_port (int): Порт, на котором запущен ZAP
        """
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.zap_api_key = zap_api_key
        self.zap_url = f'http://{zap_host}:{zap_port}'
        
        # Инициализация соединения с ZAP API
        self.zap = ZAPv2(apikey=zap_api_key, proxies={'http': self.zap_url, 'https': self.zap_url})
        logger.info(f"Соединение с ZAP установлено: {self.zap_url}")
        
        # Проверка версии ZAP
        self.zap_version = self.zap.core.version
        logger.info(f"Версия ZAP: {self.zap_version}")
        
        # Каталог профилей сканирования
        self.scan_profiles = {
            'basic': {
                'name': 'Базовое сканирование',
                'description': 'Быстрое базовое сканирование без активного тестирования',
                'active_scan': False,
                'spider_timeout': 1, # минуты
                'ajax_spider': False,
                'scan_policy': None
            },
            'standard': {
                'name': 'Стандартное сканирование',
                'description': 'Полное сканирование с активным тестированием',
                'active_scan': True,
                'spider_timeout': 2, # минуты
                'ajax_spider': True,
                'scan_policy': None
            },
            'thorough': {
                'name': 'Тщательное сканирование',
                'description': 'Полное тщательное сканирование с увеличенным таймаутом',
                'active_scan': True,
                'spider_timeout': 5, # минуты
                'ajax_spider': True,
                'scan_policy': None
            },
            'e-commerce': {
                'name': 'E-Commerce сканирование',
                'description': 'Специализированное сканирование для E-Commerce приложений',
                'active_scan': True,
                'spider_timeout': 3, # минуты
                'ajax_spider': True,
                'scan_policy': 'e-commerce-policy'
            }
        }
        
    def check_connection(self):
        """
        Проверка соединения с ZAP API.
        
        Returns:
            bool: True, если соединение установлено успешно
        """
        try:
            version = self.zap.core.version
            logger.info(f"Соединение с ZAP установлено успешно. Версия: {version}")
            return True
        except Exception as e:
            logger.error(f"Ошибка соединения с ZAP: {e}")
            return False
    
    def start_scan(self, target_url, profile_name='standard'):
        """
        Запуск сканирования с указанным профилем.
        
        Args:
            target_url (str): URL-адрес целевого веб-приложения
            profile_name (str): Имя профиля сканирования из предопределенных профилей
            
        Returns:
            dict: Результаты сканирования
        """
        if profile_name not in self.scan_profiles:
            logger.error(f"Профиль сканирования '{profile_name}' не найден")
            return None
        
        profile = self.scan_profiles[profile_name]
        logger.info(f"Начинаем сканирование '{profile['name']}' для {target_url}")
        
        try:
            # Отслеживание времени сканирования
            start_time = time.time()
            
            # Запуск сканирования целевого URL
            logger.info(f"Добавление целевого URL {target_url} в область видимости")
            self.zap.core.access_url(target_url)
            self.zap.core.new_session()
            
            # Добавление целевого URL в контекст и область
            context_id = 1
            context_name = 'scan_context'
            self.zap.context.new_context(context_name)
            self.zap.context.include_in_context(context_name, ".*")  # Включить все URL для тестирования

            
            # Запуск сканирования с пауком
            logger.info(f"Запуск традиционного паука для {target_url}")
            spider_id = self.zap.spider.scan(target_url)
            
            # Преобразуем результат в целое число, если возможно
            try:
                spider_id = int(spider_id)
            except ValueError:
                # Если не удалось преобразовать в число, используем строковый идентификатор
                logger.warning(f"Невозможно преобразовать ID паука '{spider_id}' в число. Используем строковое представление.")
            
            # Прогресс сканирования пауком
            spider_timeout_mins = profile['spider_timeout']
            spider_timeout_secs = spider_timeout_mins * 60
            spider_start_time = time.time()
            
            # Ожидание завершения сканирования пауком
            # Проверяем, получилось ли преобразовать spider_id в число
            if isinstance(spider_id, int):
                # Преобразуем результат статуса в число перед сравнением
                while int(self.zap.spider.status(spider_id)) < 100:
                    # Если превышен таймаут, прерываем сканирование
                    if time.time() - spider_start_time > spider_timeout_secs:
                        logger.warning(f"Таймаут сканирования пауком ({spider_timeout_mins} минут) превышен")
                        break
                    logger.info(f"Прогресс сканирования пауком: {self.zap.spider.status(spider_id)}%")
                    time.sleep(5)
            else:
                # Для строкового ID используем другой подход (например, просто ждем фиксированное время)
                logger.info("Ожидание завершения сканирования пауком...")
                time.sleep(spider_timeout_secs / 2)
                    
            logger.info("Сканирование пауком завершено")
            
            # Запуск AJAX-паука, если это указано в профиле
            if profile['ajax_spider']:
                try:
                    logger.info(f"Запуск AJAX-паука для {target_url}")
                    self.zap.ajaxSpider.scan(target_url)
                    
                    # Проверяем статус AJAX-паука
                    time.sleep(5)  # Даем время на запуск
                    status = self.zap.ajaxSpider.status
                    while status != 'stopped':
                        logger.info(f"AJAX-паук: {status}")
                        time.sleep(5)
                        status = self.zap.ajaxSpider.status
                        
                    logger.info("Сканирование AJAX-пауком завершено")
                except Exception as e:
                    logger.warning(f"Ошибка при использовании AJAX-паука: {e}")
                    logger.warning("Продолжаем без AJAX-паука")
                
            # Запуск активного сканирования, если это указано в профиле
            if profile['active_scan']:
                logger.info(f"Запуск активного сканирования для {target_url}")
                if profile.get('scan_policy'):
                    policy_name = profile.get('scan_policy')
                    logger.info(f"Установка политики сканирования: {policy_name}")
                    try:
                        # Проверяем наличие политики
                        policies = self.zap.ascan.scan_policy_names
                        logger.info(f"Доступные политики: {policies}")
                        
                        if policy_name in policies:
                            self.zap.ascan.set_option_scan_policy(policy_name)
                        else:
                            logger.warning(f"Политика сканирования '{policy_name}' не найдена. Используется политика по умолчанию.")
                    except Exception as e:
                        logger.error(f"Ошибка при установке политики сканирования: {e}")
                
                # Добавим информации для отладки
                logger.info(f"Текущие URL в области: {self.zap.core.urls()}")

                scan_id = self.zap.ascan.scan(target_url)
                logger.info(f"Результат вызова ascan.scan: {scan_id}")                
                # Преобразуем результат в целое число, если возможно
                try:
                    scan_id = int(scan_id)
                except ValueError:
                    # Если не удалось преобразовать в число, пропускаем ожидание
                    logger.warning(f"Невозможно преобразовать ID активного сканирования '{scan_id}' в число. Пропускаем ожидание.")
                else:
                    # Отслеживание прогресса активного сканирования
                    while int(self.zap.ascan.status(scan_id)) < 100:
                        logger.info(f"Прогресс активного сканирования: {self.zap.ascan.status(scan_id)}%")
                        time.sleep(5)
                    
                logger.info("Активное сканирование завершено")
                
            # Получение оповещений и результатов
            alerts = self.zap.core.alerts()
            
            # Расчет времени сканирования
            scan_time = time.time() - start_time
            logger.info(f"Сканирование завершено за {scan_time:.2f} секунд")
            
            # Формирование результатов
            result = {
                'target_url': target_url,
                'profile': profile,
                'scan_time': scan_time,
                'alerts': alerts,
                'alerts_count': len(alerts),
                'scan_date': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Ошибка при сканировании: {e}")
            return None
    
    def get_scan_results_dataframe(self, scan_result):
        """
        Преобразование результатов сканирования в DataFrame для дальнейшего анализа.
        
        Args:
            scan_result (dict): Результаты сканирования
            
        Returns:
            pandas.DataFrame: DataFrame с результатами сканирования
        """
        if scan_result is None or 'alerts' not in scan_result:
            return pd.DataFrame()
        
        alerts = scan_result['alerts']
        df = pd.DataFrame(alerts)
        
        return df
    
    def save_report(self, scan_result, format='json', filename=None):
        """
        Сохранение отчета о сканировании в указанном формате.
        
        Args:
            scan_result (dict): Результаты сканирования
            format (str): Формат отчета ('json', 'html', 'xml')
            filename (str): Имя файла для сохранения отчета
            
        Returns:
            str: Путь к сохраненному файлу отчета
        """
        if scan_result is None:
            logger.error("Нет результатов сканирования для сохранения")
            return None
        
        if filename is None:
            timestamp = time.strftime('%Y%m%d-%H%M%S')
            target = scan_result['target_url'].replace('https://', '').replace('http://', '').replace('/', '_')
            filename = f"zap_report_{target}_{timestamp}.{format}"
        
        try:
            if format == 'json':
                with open(filename, 'w') as f:
                    json.dump(scan_result, f, indent=4)
            elif format == 'html':
                # Получение HTML-отчета через ZAP API
                html_report = self.zap.core.htmlreport()
                with open(filename, 'w') as f:
                    f.write(html_report)
            elif format == 'xml':
                # Получение XML-отчета через ZAP API
                xml_report = self.zap.core.xmlreport()
                with open(filename, 'w') as f:
                    f.write(xml_report)
            else:
                logger.error(f"Неподдерживаемый формат отчета: {format}")
                return None
            
            logger.info(f"Отчет сохранен в файле: {filename}")
            return filename
        
        except Exception as e:
            logger.error(f"Ошибка при сохранении отчета: {e}")
            return None
        
    def shutdown(self):
        """
        Корректное завершение работы с ZAP.
        """
        try:
            logger.info("Завершение работы с ZAP")
            self.zap.core.shutdown()
            logger.info("ZAP успешно завершил работу")
        except Exception as e:
            logger.error(f"Ошибка при завершении работы ZAP: {e}")