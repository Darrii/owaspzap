"""
IntelligentAnalyzer - Модуль для интеллектуального анализа результатов сканирования.
Этот модуль предоставляет возможности для снижения количества ложных срабатываний,
классификации уязвимостей и приоритизации результатов.
"""

import logging
import json
import os
from typing import List, Dict, Any, Optional, Tuple

# Импорт модулей для интеллектуального анализа
from models.vulnerability_classifier import VulnerabilityClassifier, CVSSCalculator, PresetFilter

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('IntelligentAnalyzer')

class IntelligentAnalyzer:
    """
    Класс для интеллектуального анализа результатов сканирования OWASP ZAP.
    """
    
    def __init__(self, model_path: str = None):
        """
        Инициализация анализатора.
        
        Args:
            model_path (str): Путь к файлу сохраненной модели
        """
        # Инициализация классификатора уязвимостей с указанной моделью
        self.classifier = VulnerabilityClassifier(model_path)
        
        # CVSS оценка для приоритизации
        self.cvss_calculator = CVSSCalculator()
        
        logger.info("IntelligentAnalyzer инициализирован")
    
    def create_training_dataset(self, scan_results: List[Dict[str, Any]], labeled_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Создание обучающего датасета на основе результатов сканирования и размеченных данных.
        
        Args:
            scan_results (List[Dict[str, Any]]): Результаты сканирования
            labeled_data (List[Dict[str, Any]]): Размеченные данные с метками истинных/ложных срабатываний
            
        Returns:
            Dict[str, Any]: DataFrame с обучающими данными и метаданными
        """
        import pandas as pd
        
        # Извлекаем оповещения из результатов сканирования
        alerts = []
        for result in scan_results:
            if 'alerts' in result:
                alerts.extend(result['alerts'])
        
        # Создаем DataFrame
        alerts_df = pd.DataFrame(alerts)
        
        # Проверяем наличие необходимых столбцов
        required_columns = ['name', 'url', 'risk', 'confidence', 'description', 'solution', 'param']
        for col in required_columns:
            if col not in alerts_df.columns:
                alerts_df[col] = ''
        
        # Переименовываем столбец 'name' в 'alert' для соответствия формату
        if 'name' in alerts_df.columns:
            alerts_df['alert'] = alerts_df['name']
        
        # Конвертируем размеченные данные
        labeled_df = pd.DataFrame(labeled_data)
        
        # Объединяем данные по ключу (alert, url)
        merged_df = pd.merge(
            alerts_df,
            labeled_df[['alert', 'url', 'is_false_positive']],
            on=['alert', 'url'],
            how='inner'
        )
        
        dataset_info = {
            'dataframe': merged_df,
            'count': len(merged_df),
            'false_positives_count': merged_df['is_false_positive'].sum(),
            'true_positives_count': len(merged_df) - merged_df['is_false_positive'].sum()
        }
        
        logger.info(f"Создан обучающий датасет: {dataset_info['count']} строк, "
                   f"{dataset_info['false_positives_count']} ложных срабатываний, "
                   f"{dataset_info['true_positives_count']} истинных уязвимостей")
                   
        return dataset_info
    
    def train_model(self, training_data: Any, save_path: str = None) -> Dict[str, float]:
        """
        Обучение модели классификации для определения ложных срабатываний.
        
        Args:
            training_data: DataFrame с обучающими данными или результат метода create_training_dataset
            save_path (str): Путь для сохранения модели
            
        Returns:
            Dict[str, float]: Метрики качества модели
        """
        import pandas as pd
        
        logger.info("Обучение модели классификации...")
        
        # Проверка типа данных training_data
        if isinstance(training_data, dict) and 'dataframe' in training_data:
            df = training_data['dataframe']
        elif isinstance(training_data, pd.DataFrame):
            df = training_data
        else:
            logger.error(f"Неверный тип данных для обучения: {type(training_data)}")
            return {"error": "Неверный тип данных для обучения"}
        
        # Обучение модели с использованием VulnerabilityClassifier
        metrics = self.classifier.train(df)
        
        # Сохранение модели, если указан путь
        if save_path:
            self.classifier.save_model(save_path)
            logger.info(f"Модель сохранена в {save_path}")
        
        return metrics
    
    def analyze_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Анализ результатов сканирования с уменьшением ложных срабатываний.
        
        Args:
            scan_results (Dict[str, Any]): Результаты сканирования
            
        Returns:
            Dict[str, Any]: Обработанные результаты сканирования
        """
        logger.info("Анализ результатов сканирования...")
        
        # Проверка типа данных и преобразование, если необходимо
        if isinstance(scan_results, str):
            logger.warning(f"scan_results является строкой, попытка преобразовать в JSON")
            try:
                import json
                scan_results = json.loads(scan_results)
            except Exception as e:
                logger.error(f"Не удалось преобразовать scan_results из строки в JSON: {e}")
                # Создаем пустой словарь с базовой структурой
                return {
                    "alerts": [],
                    "alerts_count": 0,
                    "analysis_metrics": {
                        "original_count": 0,
                        "filtered_count": 0,
                        "final_count": 0,
                        "reduction_percentage": 0
                    },
                    "error": "Неверный формат данных сканирования"
                }
        
        if not isinstance(scan_results, dict):
            logger.error(f"scan_results имеет неверный тип: {type(scan_results)}")
            # Создаем пустой словарь с базовой структурой
            return {
                "alerts": [],
                "alerts_count": 0,
                "analysis_metrics": {
                    "original_count": 0,
                    "filtered_count": 0,
                    "final_count": 0,
                    "reduction_percentage": 0
                },
                "error": f"Неверный тип данных сканирования: {type(scan_results)}"
            }
        
        # Проверка наличия оповещений
        if 'alerts' not in scan_results:
            logger.error("Отсутствуют оповещения в результатах сканирования")
            scan_results['alerts'] = []
            return scan_results
        
        alerts = scan_results['alerts']
        
        # Проверка типа данных alerts
        if isinstance(alerts, str):
            logger.warning(f"alerts является строкой, попытка преобразовать в JSON")
            try:
                import json
                alerts = json.loads(alerts)
                scan_results['alerts'] = alerts
            except Exception as e:
                logger.error(f"Не удалось преобразовать alerts из строки в JSON: {e}")
                alerts = []
                scan_results['alerts'] = alerts
        
        # Проверка, что alerts является списком
        if not isinstance(alerts, list):
            logger.error(f"alerts имеет неверный тип: {type(alerts)}")
            alerts = []
            scan_results['alerts'] = alerts
        
        # Если alerts пуст, вернуть scan_results без изменений
        if not alerts:
            logger.warning("Список оповещений пуст")
            analyzed_results = scan_results.copy()
            analyzed_results['alerts_count'] = 0
            analyzed_results['analysis_metrics'] = {
                'original_count': 0,
                'filtered_count': 0,
                'final_count': 0,
                'reduction_percentage': 0
            }
            return analyzed_results
        
        # Этап 1: Применение правил фильтрации с помощью PresetFilter
        filtered_alerts, filtered_count = PresetFilter.apply_filters(alerts)
        
        # Этап 2: Применение модели классификации, если она доступна
        classified_alerts = filtered_alerts
        false_positive_count = 0
        
        if self.classifier.model is not None:
            import pandas as pd
            
            # Создаем DataFrame из оповещений
            alerts_df = pd.DataFrame(filtered_alerts)
            
            # Переименовываем поле 'name' в 'alert', если необходимо
            if 'name' in alerts_df.columns and 'alert' not in alerts_df.columns:
                alerts_df['alert'] = alerts_df['name']
            
            # Получаем предсказания модели
            try:
                predictions, probabilities = self.classifier.predict(alerts_df)
                
                # Добавляем результаты классификации к оповещениям
                classified_alerts = []
                for i, alert in enumerate(filtered_alerts):
                    # Добавление пометки и вероятности ложного срабатывания
                    alert['is_false_positive_prediction'] = bool(predictions[i])
                    alert['false_positive_probability'] = float(probabilities[i])
                    
                    # Фильтрация оповещений с высокой вероятностью ложного срабатывания
                    if predictions[i] and probabilities[i] >= 0.8:
                        false_positive_count += 1
                        # Понижаем уровень риска для вероятных ложных срабатываний
                        alert['risk_adjusted'] = 'Low'
                    else:
                        alert['risk_adjusted'] = alert.get('risk', alert.get('riskdesc', ''))
                        classified_alerts.append(alert)
                
                logger.info(f"Применена модель классификации. Выявлено {false_positive_count} вероятных ложных срабатываний.")
            except Exception as e:
                logger.error(f"Ошибка при применении модели классификации: {e}")
                # В случае ошибки классификации, используем отфильтрованные оповещения без изменений
                classified_alerts = filtered_alerts
        
        # Этап 3: Приоритизация оповещений
        prioritized_alerts = self._prioritize_alerts(classified_alerts)
        
        # Обновление результатов
        analyzed_results = scan_results.copy()
        analyzed_results['alerts'] = prioritized_alerts
        analyzed_results['alerts_count'] = len(prioritized_alerts)
        
        # Добавление метрик анализа
        analyzed_results['analysis_metrics'] = {
            'original_count': len(alerts),
            'filtered_count': len(filtered_alerts),
            'identified_false_positives': false_positive_count,
            'final_count': len(prioritized_alerts),
            'reduction_percentage': ((len(alerts) - len(prioritized_alerts)) / len(alerts) * 100) if len(alerts) > 0 else 0
        }
        
        logger.info(f"Анализ завершен. Сокращение ложных срабатываний: {analyzed_results['analysis_metrics']['reduction_percentage']:.2f}%")
        
        return analyzed_results
    
    def _prioritize_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Приоритизация оповещений на основе оценки CVSS и других факторов.
        
        Args:
            alerts (List[Dict[str, Any]]): Список оповещений
            
        Returns:
            List[Dict[str, Any]]: Приоритизированный список оповещений
        """
        # Приоритизация оповещений с использованием CVSS
        for alert in alerts:
            # Получаем уровень риска (используем скорректированный, если есть)
            risk = alert.get('risk_adjusted', alert.get('risk', alert.get('riskdesc', 'Low')))
            
            # Получаем имя оповещения
            alert_name = alert.get('name', alert.get('alert', 'Unknown Alert'))
            
            # Рассчитываем оценки CVSS с помощью CVSSCalculator
            cvss_scores = self.cvss_calculator.calculate_cvss_score(
                alert_name, 
                risk, 
                alert.get('confidence', alert.get('confidencedesc', 'Medium'))
            )
            
            # Добавляем оценки CVSS к оповещению
            alert.update(cvss_scores)
            
            # Расчет приоритета с учетом ложных срабатываний
            confidence_factor = 1.0
            if alert.get('confidence', alert.get('confidencedesc', '')) == 'High':
                confidence_factor = 1.0
            elif alert.get('confidence', alert.get('confidencedesc', '')) == 'Medium':
                confidence_factor = 0.8
            elif alert.get('confidence', alert.get('confidencedesc', '')) == 'Low':
                confidence_factor = 0.6
            
            false_positive_factor = 1.0
            if alert.get('is_false_positive_prediction', False):
                false_positive_prob = alert.get('false_positive_probability', 0.0)
                false_positive_factor = 1.0 - (false_positive_prob * 0.8)
            
            # Расчет итогового приоритета
            priority_score = cvss_scores['base_score'] * confidence_factor * false_positive_factor
            
            alert['priority_score'] = round(priority_score, 2)
        
        # Сортировка по приоритету (от высокого к низкому)
        prioritized_alerts = sorted(alerts, key=lambda x: x.get('priority_score', 0), reverse=True)
        
        return prioritized_alerts
    
    def generate_remediation_guide(self, alerts: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Создание руководства по устранению выявленных уязвимостей.
        
        Args:
            alerts (List[Dict[str, Any]]): Список оповещений
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: Руководство по устранению уязвимостей
        """
        # Группировка оповещений по типу
        grouped_alerts = {}
        
        for alert in alerts:
            alert_name = alert.get('name', alert.get('alert', 'Unknown'))
            
            if alert_name not in grouped_alerts:
                grouped_alerts[alert_name] = {
                    'alert_name': alert_name,
                    'risk': alert.get('risk', alert.get('riskdesc', 'Low')),
                    'description': alert.get('description', alert.get('desc', '')),
                    'solution': alert.get('solution', alert.get('remedy', '')),
                    'references': alert.get('reference', alert.get('refs', '')),
                    'instances': [],
                    'cvss_score': alert.get('base_score', 0)
                }
            
            grouped_alerts[alert_name]['instances'].append({
                'url': alert.get('url', ''),
                'param': alert.get('param', ''),
                'evidence': alert.get('evidence', '')
            })
        
        # Подсчет количества экземпляров и добавление в объект
        for alert_data in grouped_alerts.values():
            alert_data['instance_count'] = len(alert_data['instances'])
        
        # Сортировка по риску и количеству экземпляров
        remediation_guide = list(grouped_alerts.values())
        remediation_guide.sort(
            key=lambda x: (
                {'High': 3, 'Medium': 2, 'Low': 1, 'Informational': 0}.get(x['risk'], 0),
                x['instance_count'],
                x['cvss_score']
            ),
            reverse=True
        )
        
        # Категоризация руководства
        categorized_guide = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for guide in remediation_guide:
            if guide['risk'] == 'High':
                categorized_guide['critical'].append(guide)
            elif guide['risk'] == 'Medium':
                categorized_guide['high'].append(guide)
            elif guide['risk'] == 'Low':
                categorized_guide['medium'].append(guide)
            else:
                categorized_guide['low'].append(guide)
        
        return categorized_guide
    
    def analyze_and_summarize(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Полный анализ и резюмирование результатов сканирования.
        
        Args:
            scan_results (Dict[str, Any]): Результаты сканирования
            
        Returns:
            Dict[str, Any]: Полный анализ с рекомендациями
        """
        # Проверка типа данных
        if not isinstance(scan_results, dict):
            logger.error(f"scan_results имеет неверный тип: {type(scan_results)}")
            scan_results = {"alerts": [], "alerts_count": 0, "error": "Invalid format"}
        
        # Анализ результатов сканирования
        analyzed_results = self.analyze_scan_results(scan_results)
        
        # Проверка наличия alerts в результатах
        if 'alerts' not in analyzed_results:
            analyzed_results['alerts'] = []
        
        # Создание руководства по устранению
        remediation_guide = self.generate_remediation_guide(analyzed_results['alerts'])
        
        # Добавление руководства к результатам
        analyzed_results['remediation_guide'] = remediation_guide
        
        # Создание сводки
        summary = {
            'target_url': scan_results.get('target_url', scan_results.get('target', '')),
            'scan_date': scan_results.get('scan_date', scan_results.get('date', '')),
            'scan_time': scan_results.get('scan_time', scan_results.get('time', 0)),
            'total_alerts': scan_results.get('alerts_count', len(scan_results.get('alerts', []))),
            'analyzed_alerts': analyzed_results.get('alerts_count', 0),
            'false_positives_reduction': analyzed_results.get('analysis_metrics', {}).get('reduction_percentage', 0),
            'risk_summary': {
                'critical': len(remediation_guide['critical']),
                'high': len(remediation_guide['high']),
                'medium': len(remediation_guide['medium']),
                'low': len(remediation_guide['low'])
            },
            'top_vulnerabilities': self._get_top_vulnerabilities(analyzed_results['alerts'])
        }
        
        analyzed_results['summary'] = summary
        
        return analyzed_results
    
    def _get_top_vulnerabilities(self, alerts: List[Dict[str, Any]], top_n: int = 5) -> List[Dict[str, Any]]:
        """
        Получение ТОП-N наиболее критичных уязвимостей.
        
        Args:
            alerts (List[Dict[str, Any]]): Список оповещений
            top_n (int): Количество верхних уязвимостей
            
        Returns:
            List[Dict[str, Any]]: Список ТОП-N уязвимостей
        """
        # Сортировка оповещений по приоритету
        sorted_alerts = sorted(alerts, key=lambda x: x.get('priority_score', 0), reverse=True)
        
        # Выбор топ-N уязвимостей
        top_vulnerabilities = []
        seen_names = set()
        
        for alert in sorted_alerts:
            name = alert.get('name', alert.get('alert', ''))
            if name and name not in seen_names:
                top_vulnerabilities.append({
                    'name': name,
                    'risk': alert.get('risk', alert.get('riskdesc', '')),
                    'priority_score': alert.get('priority_score', 0),
                    'cvss_base_score': alert.get('base_score', 0)
                })
                seen_names.add(name)
            
            if len(top_vulnerabilities) >= top_n:
                break
        
        return top_vulnerabilities