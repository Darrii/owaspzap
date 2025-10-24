"""
PerformanceScanner - Расширение EnhancedScanner с улучшенной производительностью.
Этот модуль предоставляет асинхронные и параллельные возможности сканирования,
а также систему бенчмаркинга для измерения производительности.
"""

import time
import json
import asyncio
import logging
import concurrent.futures
from typing import List, Dict, Any, Optional
import pandas as pd
from EnhancedScanner import EnhancedScanner

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PerformanceScanner')

class PerformanceScanner(EnhancedScanner):
    """
    Расширение EnhancedScanner с улучшенной производительностью.
    """
    
    def __init__(self, zap_api_key='12345', zap_host='localhost', zap_port=8080):
        """
        Инициализация PerformanceScanner.
        
        Args:
            zap_api_key (str): Ключ API для ZAP
            zap_host (str): Хост, на котором запущен ZAP
            zap_port (int): Порт, на котором запущен ZAP
        """
        super().__init__(zap_api_key, zap_host, zap_port)
        
        # Расширенные профили сканирования с дополнительными настройками производительности
        self.performance_profiles = {
            'async_basic': {
                'name': 'Асинхронное базовое сканирование',
                'description': 'Базовое сканирование с асинхронным выполнением',
                'active_scan': False,
                'spider_timeout': 1,
                'ajax_spider': False,
                'scan_policy': None,
                'async_enabled': True,
                'concurrent_scans': 1
            },
            'parallel_standard': {
                'name': 'Параллельное стандартное сканирование',
                'description': 'Стандартное сканирование с параллельным выполнением',
                'active_scan': True,
                'spider_timeout': 2,
                'ajax_spider': True,
                'scan_policy': None,
                'async_enabled': False,
                'concurrent_scans': 3
            },
            'parallel_thorough': {
                'name': 'Параллельное тщательное сканирование',
                'description': 'Тщательное сканирование с параллельным выполнением',
                'active_scan': True,
                'spider_timeout': 5,
                'ajax_spider': True,
                'scan_policy': None,
                'async_enabled': False,
                'concurrent_scans': 2
            },
            'async_e-commerce': {
                'name': 'Асинхронное E-Commerce сканирование',
                'description': 'Специализированное сканирование для E-Commerce с асинхронным выполнением',
                'active_scan': True,
                'spider_timeout': 3,
                'ajax_spider': True,
                'scan_policy': 'e-commerce-policy',
                'async_enabled': True,
                'concurrent_scans': 1
            }
        }
        
        # Счетчики и метрики производительности
        self.performance_metrics = {
            'scan_times': [],
            'avg_scan_time': 0,
            'max_scan_time': 0,
            'min_scan_time': float('inf'),
            'total_urls_scanned': 0,
            'total_alerts_found': 0,
            'scans_completed': 0
        }
        
    async def async_scan(self, target_url: str, profile_name: str = 'standard') -> Dict[str, Any]:
        """
        Асинхронная версия сканирования.
        
        Args:
            target_url (str): URL-адрес целевого веб-приложения
            profile_name (str): Имя профиля сканирования
            
        Returns:
            dict: Результаты сканирования
        """
        logger.info(f"Начинаем асинхронное сканирование {target_url} с профилем {profile_name}")
        
        # Проверяем профиль
        if profile_name not in self.scan_profiles and profile_name not in self.performance_profiles:
            logger.error(f"Профиль сканирования '{profile_name}' не найден")
            return None
        
        # Определяем используемый профиль
        profile = self.performance_profiles.get(profile_name, self.scan_profiles.get(profile_name))
        
        # Запускаем сканирование в отдельном потоке через executor
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, 
            lambda: self.start_scan(target_url, profile_name)
        )
        
        return result
        
    async def run_multiple_async_scans(self, targets: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Запуск множественных асинхронных сканирований.
        
        Args:
            targets (List[Dict[str, str]]): Список целей с профилями
                Пример: [{'url': 'https://example.com', 'profile': 'standard'}]
            
        Returns:
            List[Dict[str, Any]]: Список результатов сканирований
        """
        logger.info(f"Запуск асинхронного сканирования для {len(targets)} целей")
        
        tasks = []
        for target in targets:
            url = target['url']
            profile = target.get('profile', 'standard')
            tasks.append(self.async_scan(url, profile))
        
        results = await asyncio.gather(*tasks)
        return results
    
    def scan_multiple_targets(self, targets: List[Dict[str, str]], max_workers: int = 3) -> List[Dict[str, Any]]:
        """
        Запуск параллельного сканирования для нескольких целей.
        
        Args:
            targets (List[Dict[str, str]]): Список целей с профилями
                Пример: [{'url': 'https://example.com', 'profile': 'standard'}]
            max_workers (int): Максимальное количество параллельных процессов
            
        Returns:
            List[Dict[str, Any]]: Список результатов сканирований
        """
        logger.info(f"Запуск параллельного сканирования для {len(targets)} целей с {max_workers} рабочими процессами")
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Создаем список задач
            future_to_url = {}
            for target in targets:
                url = target['url']
                profile = target.get('profile', 'standard')
                future = executor.submit(self.start_scan, url, profile)
                future_to_url[future] = url
            
            # Обрабатываем результаты по мере их готовности
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"Сканирование {url} завершено успешно")
                except Exception as e:
                    logger.error(f"Ошибка при сканировании {url}: {e}")
                    results.append({'url': url, 'error': str(e)})
                    
        return results
    
    def benchmark_scan(self, target_url: str, profiles: List[str], iterations: int = 1) -> Dict[str, Any]:
        """
        Проведение бенчмарка сканирования с разными профилями.
        
        Args:
            target_url (str): URL-адрес целевого веб-приложения
            profiles (List[str]): Список профилей для сравнения
            iterations (int): Количество повторов для каждого профиля
            
        Returns:
            Dict[str, Any]: Результаты бенчмарка
        """
        logger.info(f"Запуск бенчмарка для {target_url} с профилями {profiles}, {iterations} итераций")
        
        benchmark_results = {}
        
        for profile in profiles:
            profile_results = {
                'times': [],
                'avg_time': 0,
                'alerts_counts': [],
                'avg_alerts': 0
            }
            
            for i in range(iterations):
                logger.info(f"Профиль {profile}, итерация {i+1}/{iterations}")
                
                start_time = time.time()
                result = self.start_scan(target_url, profile)
                scan_time = time.time() - start_time
                
                if result:
                    profile_results['times'].append(scan_time)
                    profile_results['alerts_counts'].append(result['alerts_count'])
                
            # Расчет средних показателей
            if profile_results['times']:
                profile_results['avg_time'] = sum(profile_results['times']) / len(profile_results['times'])
                profile_results['avg_alerts'] = sum(profile_results['alerts_counts']) / len(profile_results['alerts_counts'])
                
            benchmark_results[profile] = profile_results
        
        # Сравнение профилей
        comparison = self._compare_benchmark_results(benchmark_results)
        
        return {
            'target_url': target_url,
            'profiles': benchmark_results,
            'comparison': comparison
        }
    
    def _compare_benchmark_results(self, benchmark_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Сравнение результатов бенчмарка между профилями.
        
        Args:
            benchmark_results (Dict[str, Dict[str, Any]]): Результаты бенчмарка
            
        Returns:
            Dict[str, Any]: Сравнительный анализ
        """
        if not benchmark_results:
            return {}
        
        fastest_profile = None
        fastest_time = float('inf')
        
        most_thorough_profile = None
        most_alerts = -1
        
        best_performance_ratio = None
        best_ratio = -1
        
        for profile, results in benchmark_results.items():
            if 'avg_time' in results and results['avg_time'] > 0:
                # Определение самого быстрого профиля
                if results['avg_time'] < fastest_time:
                    fastest_time = results['avg_time']
                    fastest_profile = profile
                
                # Определение самого тщательного профиля
                if results['avg_alerts'] > most_alerts:
                    most_alerts = results['avg_alerts']
                    most_thorough_profile = profile
                
                # Определение лучшего соотношения скорость/качество
                ratio = results['avg_alerts'] / results['avg_time'] if results['avg_time'] > 0 else 0
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_performance_ratio = profile
        
        return {
            'fastest_profile': fastest_profile,
            'fastest_time': fastest_time,
            'most_thorough_profile': most_thorough_profile,
            'most_alerts': most_alerts,
            'best_performance_ratio': best_performance_ratio,
            'best_ratio': best_ratio
        }
    
    def save_benchmark_results(self, benchmark_results: Dict[str, Any], filename: str = None) -> str:
        """
        Сохранение результатов бенчмарка в файл.
        
        Args:
            benchmark_results (Dict[str, Any]): Результаты бенчмарка
            filename (str): Имя файла для сохранения
            
        Returns:
            str: Путь к сохраненному файлу
        """
        if not benchmark_results:
            logger.error("Нет результатов бенчмарка для сохранения")
            return None
        
        if filename is None:
            timestamp = time.strftime('%Y%m%d-%H%M%S')
            target = benchmark_results['target_url'].replace('https://', '').replace('http://', '').replace('/', '_')
            filename = f"benchmark_{target}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(benchmark_results, f, indent=4)
            
            logger.info(f"Результаты бенчмарка сохранены в файле: {filename}")
            return filename
        except Exception as e:
            logger.error(f"Ошибка при сохранении результатов бенчмарка: {e}")
            return None