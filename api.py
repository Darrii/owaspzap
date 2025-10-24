"""
ZAP Enhanced Reporting API
Этот модуль предоставляет API интерфейс для работы с результатами сканирования,
их анализа и формирования отчетов.
"""

import os
import json
import logging
import uvicorn
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Query, File, UploadFile, BackgroundTasks, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime
from pydantic import BaseModel, HttpUrl

# Импорт классов из проекта
from EnhancedScanner import EnhancedScanner
from PerformanceScanner import PerformanceScanner
from IntelligentAnalyzer import IntelligentAnalyzer

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("zap_api")

# Директории для хранения данных
REPORTS_DIR = os.path.join(os.getcwd(), "reports")
MODELS_DIR = os.path.join(os.getcwd(), "models")
SCANS_DIR = os.path.join(os.getcwd(), "scans")

# Создание директорий, если они не существуют
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(SCANS_DIR, exist_ok=True)

# Модели данных
class ScanRequest(BaseModel):
    """Запрос на сканирование"""
    target_url: HttpUrl
    profile: str = "standard"
    async_scan: bool = False
    analyze_results: bool = True
    description: Optional[str] = None

class Target(BaseModel):
    """Целевой URL для сканирования"""
    url: HttpUrl
    profile: str = "standard"

class MultiScanRequest(BaseModel):
    """Запрос на множественное сканирование"""
    targets: List[Target]
    max_workers: int = 3
    async_scan: bool = False
    analyze_results: bool = True
    description: Optional[str] = None

class AnalyzeRequest(BaseModel):
    """Запрос на анализ результатов сканирования"""
    scan_id: str
    generate_report: bool = True
    model_id: Optional[str] = None

# Инициализация FastAPI
app = FastAPI(
    title="ZAP Enhanced Reporting API",
    description="API для расширенного сканирования и отчетности на базе OWASP ZAP",
    version="1.0.0"
)

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Хранилище запущенных сканирований
scans_store = {}
# Хранилище сгенерированных отчетов
reports_store = {}
# Хранилище моделей классификации
models_store = {}

# Роутеры API
@app.get("/", tags=["Info"])
async def root():
    """
    Корневой маршрут, возвращает информацию о API.
    """
    return {
        "name": "ZAP Enhanced Reporting API",
        "version": "1.0.0",
        "description": "API для расширенного сканирования и отчетности на базе OWASP ZAP"
    }

@app.get("/status", tags=["Info"])
async def get_status():
    try:
        # Создание сканера
        scanner = EnhancedScanner()
        
        # Проверка соединения с ZAP
        zap_status = scanner.check_connection()
        
        return {
            "api_status": "running",
            "zap_status": "connected" if zap_status else "disconnected",
            "scans_count": len(scans_store),
            "reports_count": len(reports_store),
            "models_count": len(models_store)
        }
    except Exception as e:
        logger.error(f"Ошибка при получении статуса: {e}")
        return {
            "api_status": "running",
            "zap_status": "error",
            "error": str(e)
        }

# СКАНИРОВАНИЕ
@app.post("/scan", tags=["Scanning"])
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Запускает новое сканирование.
    """
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    scan_info = {
        "id": scan_id,
        "target_url": str(request.target_url),
        "profile": request.profile,
        "async_scan": request.async_scan,
        "analyze_results": request.analyze_results,
        "description": request.description,
        "status": "scheduled",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "result": None
    }
    
    # Сохранение информации о сканировании
    scans_store[scan_id] = scan_info
    
    # Запуск сканирования в фоновом режиме
    background_tasks.add_task(
        perform_scan,
        scan_id,
        str(request.target_url),
        request.profile,
        request.async_scan,
        request.analyze_results
    )
    
    return {
        "scan_id": scan_id,
        "status": "scheduled",
        "message": "Сканирование запущено"
    }

@app.post("/scan/multi", tags=["Scanning"])
async def start_multi_scan(
    request: MultiScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Запускает множественное сканирование.
    """
    scan_id = f"multi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    targets = [{"url": str(target.url), "profile": target.profile} for target in request.targets]
    
    scan_info = {
        "id": scan_id,
        "targets": targets,
        "max_workers": request.max_workers,
        "async_scan": request.async_scan,
        "analyze_results": request.analyze_results,
        "description": request.description,
        "status": "scheduled",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "results": {}
    }
    
    # Сохранение информации о сканировании
    scans_store[scan_id] = scan_info
    
    # Запуск множественного сканирования в фоновом режиме
    background_tasks.add_task(
        perform_multi_scan,
        scan_id,
        targets,
        request.max_workers,
        request.async_scan,
        request.analyze_results
    )
    
    return {
        "scan_id": scan_id,
        "status": "scheduled",
        "message": f"Множественное сканирование для {len(targets)} целей запущено"
    }

@app.get("/scan/{scan_id}", tags=["Scanning"])
async def get_scan_status(scan_id: str):
    """
    Получает статус сканирования.
    """
    if scan_id not in scans_store:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    scan_info = scans_store[scan_id]
    
    return scan_info

@app.get("/scans", tags=["Scanning"])
async def get_scans(
    limit: int = Query(10, description="Максимальное количество сканирований"),
    offset: int = Query(0, description="Смещение для пагинации"),
    status: Optional[str] = Query(None, description="Фильтр по статусу")
):
    """
    Получает список сканирований.
    """
    scans = list(scans_store.values())
    
    # Фильтрация по статусу, если указан
    if status:
        scans = [scan for scan in scans if scan["status"] == status]
    
    # Сортировка по дате создания
    scans.sort(key=lambda x: x["created_at"], reverse=True)
    
    # Пагинация
    total = len(scans)
    scans = scans[offset:offset+limit]
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "scans": scans
    }

# АНАЛИЗ
@app.post("/analyze", tags=["Analysis"])
async def analyze_scan(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks
):
    """
    Анализирует результаты сканирования.
    """
    if request.scan_id not in scans_store:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    scan_info = scans_store[request.scan_id]
    
    if scan_info["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail="Сканирование еще не завершено или уже анализируется"
        )
    
    if "result" not in scan_info or not scan_info["result"]:
        raise HTTPException(
            status_code=400,
            detail="Результаты сканирования отсутствуют"
        )
    
    # Обновление статуса
    scan_info["status"] = "analyzing"
    scan_info["updated_at"] = datetime.now().isoformat()
    scans_store[request.scan_id] = scan_info
    
    # Запуск анализа в фоновом режиме
    background_tasks.add_task(
        perform_analysis,
        request.scan_id,
        request.generate_report,
        request.model_id
    )
    
    return {
        "scan_id": request.scan_id,
        "status": "analyzing",
        "message": "Анализ запущен"
    }

# ОТЧЕТЫ
@app.get("/reports", tags=["Reports"])
async def get_reports(
    limit: int = Query(10, description="Максимальное количество отчетов"),
    offset: int = Query(0, description="Смещение для пагинации")
):
    """
    Получает список сгенерированных отчетов.
    """
    reports = list(reports_store.values())
    
    # Сортировка по дате создания
    reports.sort(key=lambda x: x["created_at"], reverse=True)
    
    # Пагинация
    total = len(reports)
    reports = reports[offset:offset+limit]
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "reports": reports
    }

@app.get("/report/{report_id}", tags=["Reports"])
async def get_report(report_id: str):
    """
    Получает информацию об отчете.
    """
    if report_id not in reports_store:
        raise HTTPException(status_code=404, detail="Отчет не найден")
    
    report_info = reports_store[report_id]
    
    return report_info

@app.get("/report/{report_id}/download", tags=["Reports"])
async def download_report(report_id: str, format: str = "json"):
    """
    Скачивает отчет в указанном формате.
    """
    if report_id not in reports_store:
        raise HTTPException(status_code=404, detail="Отчет не найден")
    
    report_info = reports_store[report_id]
    
    report_file = None
    if format == "json":
        report_file = report_info.get("json_file")
    elif format == "html":
        report_file = report_info.get("html_file")
    elif format == "pdf":
        report_file = report_info.get("pdf_file")
    else:
        raise HTTPException(status_code=400, detail="Неподдерживаемый формат отчета")
    
    if not report_file or not os.path.exists(report_file):
        raise HTTPException(status_code=404, detail=f"Отчет в формате {format} не найден")
    
    return FileResponse(report_file, filename=os.path.basename(report_file))

# МОДЕЛИ
@app.get("/models", tags=["Models"])
async def get_models():
    """
    Получает список доступных моделей классификации.
    """
    return list(models_store.values())

@app.post("/model/train", tags=["Models"])
async def train_model(
    scan_id: str = Body(..., description="ID сканирования для обучения"),
    labeled_data: List[Dict[str, Any]] = Body(..., description="Размеченные данные для обучения"),
    model_name: Optional[str] = Body(None, description="Название модели"),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """
    Обучает новую модель классификации.
    """
    if scan_id not in scans_store:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    model_id = f"model_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    if not model_name:
        model_name = f"Model {model_id}"
    
    model_info = {
        "id": model_id,
        "name": model_name,
        "scan_id": scan_id,
        "status": "training",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "metrics": None,
        "path": os.path.join(MODELS_DIR, f"{model_id}.pkl")
    }
    
    # Сохранение информации о модели
    models_store[model_id] = model_info
    
    # Запуск обучения модели в фоновом режиме
    background_tasks.add_task(
        train_model_task,
        model_id,
        scan_id,
        labeled_data
    )
    
    return {
        "model_id": model_id,
        "status": "training",
        "message": "Обучение модели запущено"
    }

# ФУНКЦИИ ДЛЯ ФОНОВЫХ ЗАДАЧ
async def perform_scan(
    scan_id: str,
    target_url: str,
    profile: str,
    async_scan: bool,
    analyze_results: bool
):
    """
    Выполняет сканирование.
    """
    try:
        logger.info(f"Запуск сканирования {scan_id} для {target_url}")
        
        # Обновление статуса
        scan_info = scans_store[scan_id]
        scan_info["status"] = "running"
        scan_info["updated_at"] = datetime.now().isoformat()
        scans_store[scan_id] = scan_info
        
        # Создание сканера
        scanner = EnhancedScanner()
        
        # Запуск сканирования
        result = scanner.start_scan(target_url, profile)
        
        if not result:
            raise Exception("Сканирование не вернуло результатов")
        
        # Сохранение результатов
        scan_file = os.path.join(SCANS_DIR, f"{scan_id}.json")
        with open(scan_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=4)
        
        # Обновление информации о сканировании
        scan_info["status"] = "completed"
        scan_info["updated_at"] = datetime.now().isoformat()
        scan_info["result"] = result
        scan_info["file_path"] = scan_file
        scans_store[scan_id] = scan_info
        
        logger.info(f"Сканирование {scan_id} завершено успешно")
        
        # Запуск анализа, если необходимо
        if analyze_results:
            await perform_analysis(scan_id, True)
        
    except Exception as e:
        logger.error(f"Ошибка при сканировании {scan_id}: {e}")
        
        # Обновление статуса
        if scan_id in scans_store:
            scan_info = scans_store[scan_id]
            scan_info["status"] = "error"
            scan_info["error"] = str(e)
            scan_info["updated_at"] = datetime.now().isoformat()
            scans_store[scan_id] = scan_info

async def perform_multi_scan(
    scan_id: str,
    targets: List[Dict[str, str]],
    max_workers: int,
    async_scan: bool,
    analyze_results: bool
):
    """
    Выполняет множественное сканирование.
    """
    try:
        logger.info(f"Запуск множественного сканирования {scan_id} для {len(targets)} целей")
        
        # Обновление статуса
        scan_info = scans_store[scan_id]
        scan_info["status"] = "running"
        scan_info["updated_at"] = datetime.now().isoformat()
        scans_store[scan_id] = scan_info
        
        # Создание сканера
        scanner = PerformanceScanner()
        
        # Запуск множественного сканирования
        results = scanner.scan_multiple_targets(targets, max_workers)
        
        if not results:
            raise Exception("Множественное сканирование не вернуло результатов")
        
        # Сохранение результатов
        scan_file = os.path.join(SCANS_DIR, f"{scan_id}.json")
        with open(scan_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=4)
        
        # Обновление информации о сканировании
        scan_info["status"] = "completed"
        scan_info["updated_at"] = datetime.now().isoformat()
        scan_info["results"] = results
        scan_info["file_path"] = scan_file
        scans_store[scan_id] = scan_info
        
        logger.info(f"Множественное сканирование {scan_id} завершено успешно")
        
        # Запуск анализа, если необходимо
        if analyze_results:
            for i, result in enumerate(results):
                if isinstance(result, dict) and 'target_url' in result:
                    result_scan_id = f"{scan_id}_target_{i}"
                    
                    # Сохранение результата как отдельного сканирования
                    scans_store[result_scan_id] = {
                        "id": result_scan_id,
                        "target_url": result['target_url'],
                        "profile": result['profile']['name'],
                        "status": "completed",
                        "created_at": datetime.now().isoformat(),
                        "updated_at": datetime.now().isoformat(),
                        "result": result,
                        "parent_scan_id": scan_id
                    }
                    
                    # Анализ результата
                    await perform_analysis(result_scan_id, True)
        
    except Exception as e:
        logger.error(f"Ошибка при множественном сканировании {scan_id}: {e}")
        
        # Обновление статуса
        if scan_id in scans_store:
            scan_info = scans_store[scan_id]
            scan_info["status"] = "error"
            scan_info["error"] = str(e)
            scan_info["updated_at"] = datetime.now().isoformat()
            scans_store[scan_id] = scan_info

async def perform_analysis(
    scan_id: str,
    generate_report: bool = True,
    model_id: Optional[str] = None
):
    """
    Выполняет анализ результатов сканирования.
    """
    try:
        logger.info(f"Запуск анализа результатов сканирования {scan_id}")
        
        # Обновление статуса
        scan_info = scans_store[scan_id]
        scan_info["status"] = "analyzing"
        scan_info["updated_at"] = datetime.now().isoformat()
        scans_store[scan_id] = scan_info
        
        # Получение результатов сканирования
        scan_result = scan_info["result"]
        
        # Создание анализатора
        model_path = None
        if model_id and model_id in models_store:
            model_path = models_store[model_id]["path"]
        
        analyzer = IntelligentAnalyzer(model_path)
        
        # Полный анализ результатов
        analyzed_results = analyzer.analyze_and_summarize(scan_result)
        
        # Сохранение результатов анализа
        analysis_file = os.path.join(REPORTS_DIR, f"analysis_{scan_id}.json")
        with open(analysis_file, 'w', encoding='utf-8') as f:
            json.dump(analyzed_results, f, ensure_ascii=False, indent=4)
        
        # Обновление информации о сканировании
        scan_info["status"] = "analyzed"
        scan_info["updated_at"] = datetime.now().isoformat()
        scan_info["analyzed_result"] = analyzed_results
        scan_info["analysis_file_path"] = analysis_file
        scans_store[scan_id] = scan_info
        
        logger.info(f"Анализ результатов сканирования {scan_id} завершен успешно")
        
        # Генерация отчета, если необходимо
        if generate_report:
            await generate_scan_report(scan_id, analyzed_results)
        
    except Exception as e:
        logger.error(f"Ошибка при анализе результатов сканирования {scan_id}: {e}")
        
        # Обновление статуса
        if scan_id in scans_store:
            scan_info = scans_store[scan_id]
            scan_info["status"] = "error"
            scan_info["error"] = str(e)
            scan_info["updated_at"] = datetime.now().isoformat()
            scans_store[scan_id] = scan_info

async def generate_scan_report(
    scan_id: str,
    analyzed_results: Dict[str, Any]
):
    """
    Генерирует отчет на основе результатов анализа.
    """
    try:
        logger.info(f"Генерация отчета для сканирования {scan_id}")
        
        # Создание идентификатора отчета
        report_id = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Генерация JSON-отчета
        json_file = os.path.join(REPORTS_DIR, f"{report_id}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(analyzed_results, f, ensure_ascii=False, indent=4)
        
        # Генерация HTML-отчета
        # Здесь вы можете добавить код для генерации HTML-отчета
        html_file = os.path.join(REPORTS_DIR, f"{report_id}.html")
        
        # Временное решение - просто копируем JSON в HTML с некоторым форматированием
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write("<!DOCTYPE html>\n")
            f.write("<html>\n<head>\n<title>ZAP Scan Report</title>\n")
            f.write("<style>body{font-family:Arial;}</style>\n</head>\n<body>\n")
            f.write("<h1>ZAP Scan Report</h1>\n")
            f.write(f"<h2>Target: {analyzed_results.get('target_url', 'N/A')}</h2>\n")
            f.write(f"<p>Date: {analyzed_results.get('scan_date', 'N/A')}</p>\n")
            f.write("<pre>" + html.escape(json.dumps(analyzed_results, indent=4)) + "</pre>\n")
            f.write("</body>\n</html>")
        
        # Сохранение информации об отчете
        report_info = {
            "id": report_id,
            "scan_id": scan_id,
            "target_url": analyzed_results.get("target_url", ""),
            "created_at": datetime.now().isoformat(),
            "json_file": json_file,
            "html_file": html_file,
            "summary": analyzed_results.get("summary", {})
        }
        
        reports_store[report_id] = report_info
        
        # Обновление информации о сканировании
        if scan_id in scans_store:
            scan_info = scans_store[scan_id]
            scan_info["report_id"] = report_id
            scan_info["updated_at"] = datetime.now().isoformat()
            scans_store[scan_id] = scan_info
        
        logger.info(f"Отчет {report_id} для сканирования {scan_id} сгенерирован успешно")
        
    except Exception as e:
        logger.error(f"Ошибка при генерации отчета для сканирования {scan_id}: {e}")

async def train_model_task(
    model_id: str,
    scan_id: str,
    labeled_data: List[Dict[str, Any]]
):
    """
    Обучает модель классификации.
    """
    try:
        logger.info(f"Запуск обучения модели {model_id}")
        
        # Обновление статуса
        model_info = models_store[model_id]
        model_info["status"] = "training"
        model_info["updated_at"] = datetime.now().isoformat()
        models_store[model_id] = model_info
        
        # Получение результатов сканирования
        scan_info = scans_store[scan_id]
        scan_result = scan_info["result"]
        
        # Создание анализатора
        analyzer = IntelligentAnalyzer()
        
        # Создание обучающего датасета
        training_df = analyzer.create_training_dataset([scan_result], labeled_data)
        
        # Обучение модели
        model_path = model_info["path"]
        analyzer.train_model(training_df, model_path)
        
        # Получение метрик модели
        # В реальном проекте здесь должны быть метрики из модели
        metrics = {
            "accuracy": 0.95,  # Пример
            "precision": 0.92,  # Пример
            "recall": 0.90,  # Пример
            "f1_score": 0.91  # Пример
        }
        
        # Обновление информации о модели
        model_info["status"] = "completed"
        model_info["updated_at"] = datetime.now().isoformat()
        model_info["metrics"] = metrics
        models_store[model_id] = model_info
        
        logger.info(f"Обучение модели {model_id} завершено успешно")
        
    except Exception as e:
        logger.error(f"Ошибка при обучении модели {model_id}: {e}")
        
        # Обновление статуса
        if model_id in models_store:
            model_info = models_store[model_id]
            model_info["status"] = "error"
            model_info["error"] = str(e)
            model_info["updated_at"] = datetime.now().isoformat()
            models_store[model_id] = model_info

# Монтирование статических файлов (если будет веб-интерфейс)
# app.mount("/static", StaticFiles(directory="static"), name="static")

def start_api():
    """
    Запускает FastAPI сервер.
    """
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    start_api()