import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';
import ErrorBoundary from './ErrorBoundary';
import ScanDetails from './ScanDetails';

function App() {
  const [activeTab, setActiveTab] = useState("scans");
  const [isLoading, setIsLoading] = useState(false);
  const [alertMessage, setAlertMessage] = useState(null);
  const [alertType, setAlertType] = useState('info');
  const [scans, setScans] = useState([]);
  const [reports, setReports] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [apiStatus, setApiStatus] = useState(null);
  
  // Форма нового сканирования
  const [targetUrl, setTargetUrl] = useState("");
  const [profile, setProfile] = useState("standard");
  const [analyzeResults, setAnalyzeResults] = useState(true);
  const [description, setDescription] = useState("");
  
  // API базовый URL
  const API_URL = 'http://localhost:8000';

  // Отображение оповещения с автоматическим скрытием
  const displayAlert = (message, type = 'info') => {
    setAlertMessage(message);
    setAlertType(type);
    
    // Скрыть оповещение через 5 секунд
    setTimeout(() => {
      setAlertMessage(null);
    }, 5000);
  };

  // Проверка статуса API
  const checkApiStatus = async () => {
    try {
      const response = await axios.get(`${API_URL}/status`);
      setApiStatus(response.data);
    } catch (error) {
      console.error("Error checking API status:", error);
      setApiStatus({ api_status: "error", error: error.message });
      displayAlert(`Ошибка при проверке статуса API: ${error.message}`, 'error');
    }
  };

  // Получение списка сканирований
  const fetchScans = async () => {
    setIsLoading(true);
    try {
      const response = await axios.get(`${API_URL}/scans`);
      setScans(response.data.scans || []);
    } catch (error) {
      console.error("Error fetching scans:", error);
      displayAlert(`Ошибка при получении списка сканирований: ${error.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  // Получение списка отчетов
  const fetchReports = async () => {
    setIsLoading(true);
    try {
      const response = await axios.get(`${API_URL}/reports`);
      setReports(response.data.reports || []);
    } catch (error) {
      console.error("Error fetching reports:", error);
      displayAlert(`Ошибка при получении списка отчетов: ${error.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  // Запуск нового сканирования
  const startScan = async (event) => {
    event.preventDefault();
    setIsLoading(true);
    try {
      const response = await axios.post(`${API_URL}/scan`, {
        target_url: targetUrl,
        profile,
        analyze_results: analyzeResults,
        description
      });
      
      displayAlert(`Сканирование запущено успешно! ID: ${response.data.scan_id}`, 'success');
      
      // Очистка формы
      setTargetUrl("");
      setDescription("");
      
      // Переключение на вкладку со сканированиями
      setActiveTab("scans");
      
      // Обновление списка сканирований
      fetchScans();
    } catch (error) {
      console.error("Error starting scan:", error);
      displayAlert(`Ошибка при запуске сканирования: ${error.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  // Анализ результатов сканирования
  const analyzeScan = async (scanId) => {
    setIsLoading(true);
    try {
      const response = await axios.post(`${API_URL}/analyze`, {
        scan_id: scanId,
        generate_report: true
      });
      
      displayAlert(`Анализ запущен успешно! ID сканирования: ${response.data.scan_id}`, 'success');
      
      // Обновление списка сканирований
      fetchScans();
    } catch (error) {
      console.error("Error analyzing scan:", error);
      displayAlert(`Ошибка при анализе результатов: ${error.message}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  // Получение деталей сканирования
  const fetchScanDetails = async (scanId) => {
    setIsLoading(true);
    try {
      const response = await axios.get(`${API_URL}/scan/${scanId}`);
      console.log("Получены детали сканирования:", response.data);
      setSelectedScan(response.data);
    } catch (error) {
      console.error("Error fetching scan details:", error);
      // Создаем минимальный объект с ошибкой
      setSelectedScan({
        id: scanId,
        error: `Ошибка при получении деталей: ${error.message}`
      });
    } finally {
      setIsLoading(false);
    }
  };
  
  // Обработка выбора сканирования
  const handleSelectScan = (scan) => {
    // Загружаем полные детали сканирования
    fetchScanDetails(scan.id);
  };

  // Обработка возврата из деталей сканирования
  const handleBackFromDetails = () => {
    setSelectedScan(null);
    fetchScans();
  };

  // При монтировании компонента
  useEffect(() => {
    checkApiStatus();
    fetchScans();

    // Периодическое обновление статуса API и списка сканирований
    const intervalId = setInterval(() => {
      checkApiStatus();
      if (activeTab === "scans" && !selectedScan) {
        fetchScans();
      }
    }, 10000);

    // Очистка интервала при размонтировании
    return () => clearInterval(intervalId);
  }, [activeTab, selectedScan]);

  // При смене вкладки
  useEffect(() => {
    // Сброс текущего сканирования при переключении вкладок
    if (selectedScan) {
      setSelectedScan(null);
    }

    // Загрузка данных для соответствующей вкладки
    if (activeTab === "scans") {
      fetchScans();
    } else if (activeTab === "reports") {
      fetchReports();
    }

    // Сброс оповещения при смене вкладки
    setAlertMessage(null);
  }, [activeTab]);

  // Компонент загрузки
  const LoadingSpinner = () => (
    <div className="loading-spinner">
      <div className="spinner"></div>
    </div>
  );

  // Компонент оповещения
  const Alert = ({ type, message }) => {
    const alertClasses = {
      success: "alert alert-success",
      error: "alert alert-error",
      info: "alert alert-info",
      warning: "alert alert-warning"
    };

    return (
      <div className={alertClasses[type]} role="alert">
        {message}
      </div>
    );
  };

  // Компонент списка сканирований
  const ScansList = () => {
    if (isLoading) {
      return <LoadingSpinner />;
    }

    if (!scans || scans.length === 0) {
      return (
        <div className="text-center py-4">
          <p className="text-gray-500">Нет доступных сканирований</p>
        </div>
      );
    }

    return (
      <div className="scans-list">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Цель</th>
              <th>Профиль</th>
              <th>Статус</th>
              <th>Дата</th>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => (
              <tr key={scan.id}>
                <td>{scan.id.substring(0, 8)}...</td>
                <td>
                  {scan.target_url ? (
                    <a href={scan.target_url} target="_blank" rel="noopener noreferrer">
                      {scan.target_url.replace(/^https?:\/\//, '').substring(0, 30)}
                      {scan.target_url.length > 30 ? '...' : ''}
                    </a>
                  ) : (
                    <span>Нет данных</span>
                  )}
                </td>
                <td>{scan.profile}</td>
                <td>
                  <span className={`status status-${scan.status}`}>
                    {scan.status}
                  </span>
                </td>
                <td>{new Date(scan.created_at).toLocaleString()}</td>
                <td>
                  <button
                    onClick={() => handleSelectScan(scan)}
                    className="btn btn-primary btn-sm"
                  >
                    Подробнее
                  </button>
                  {scan.status === 'completed' && (
                    <button
                      onClick={() => analyzeScan(scan.id)}
                      className="btn btn-success btn-sm ml-2"
                    >
                      Анализировать
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  // Компонент списка отчетов
  const ReportsList = () => {
    if (isLoading) {
      return <LoadingSpinner />;
    }

    if (!reports || reports.length === 0) {
      return (
        <div className="text-center py-4">
          <p className="text-gray-500">Нет доступных отчетов</p>
        </div>
      );
    }

    return (
      <div className="reports-list">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Цель</th>
              <th>Дата</th>
              <th>Сводка</th>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {reports.map(report => (
              <tr key={report.id}>
                <td>{report.id.substring(0, 8)}...</td>
                <td>
                  {report.target_url ? (
                    <a href={report.target_url} target="_blank" rel="noopener noreferrer">
                      {report.target_url.replace(/^https?:\/\//, '').substring(0, 30)}
                      {report.target_url.length > 30 ? '...' : ''}
                    </a>
                  ) : (
                    <span>Нет данных</span>
                  )}
                </td>
                <td>{new Date(report.created_at).toLocaleString()}</td>
                <td>
                  {report.summary && (
                    <div className="risk-summary">
                      <span className="risk-critical">{report.summary.risk_summary?.critical || 0}</span>
                      <span className="risk-high">{report.summary.risk_summary?.high || 0}</span>
                      <span className="risk-medium">{report.summary.risk_summary?.medium || 0}</span>
                      <span className="risk-low">{report.summary.risk_summary?.low || 0}</span>
                    </div>
                  )}
                </td>
                <td>
                  <a 
                    href={`${API_URL}/report/${report.id}/download?format=json`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-primary btn-sm"
                  >
                    JSON
                  </a>
                  <a 
                    href={`${API_URL}/report/${report.id}/download?format=html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-success btn-sm ml-2"
                  >
                    HTML
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  // Форма нового сканирования
  const ScanForm = () => (
    <form onSubmit={startScan} className="scan-form">
      <div className="form-group">
        <label htmlFor="target_url">Целевой URL:</label>
        <input
          type="url"
          id="target_url"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          required
          className="form-control"
          placeholder="https://example.com"
        />
      </div>
      
      <div className="form-group">
        <label htmlFor="profile">Профиль сканирования:</label>
        <select
          id="profile"
          value={profile}
          onChange={(e) => setProfile(e.target.value)}
          className="form-control"
        >
          <option value="basic">Базовый</option>
          <option value="standard">Стандартный</option>
          <option value="thorough">Тщательный</option>
          <option value="e-commerce">E-Commerce</option>
          <option value="async_basic">Асинхронный базовый</option>
          <option value="fast_scan">Быстрый</option>
          <option value="api_scan">API</option>
        </select>
      </div>
      
      <div className="form-group">
        <label htmlFor="description">Описание (опционально):</label>
        <textarea
          id="description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className="form-control"
          rows="3"
        ></textarea>
      </div>
      
      <div className="form-check">
        <input
          type="checkbox"
          id="analyze_results"
          checked={analyzeResults}
          onChange={(e) => setAnalyzeResults(e.target.checked)}
          className="form-check-input"
        />
        <label htmlFor="analyze_results" className="form-check-label">
          Анализировать результаты
        </label>
      </div>
      
      <button
        type="submit"
        disabled={isLoading}
        className="btn btn-primary"
      >
        {isLoading ? "Запуск..." : "Запустить сканирование"}
      </button>
    </form>
  );

  // Рендеринг контента в зависимости от активной вкладки
  const renderContent = () => {
    if (selectedScan) {
      return (
        <ErrorBoundary>
          <ScanDetails scan={selectedScan} onBack={handleBackFromDetails} />
        </ErrorBoundary>
      );
    }

    switch (activeTab) {
      case "new-scan":
        return <ScanForm />;
      case "reports":
        return <ReportsList />;
      case "scans":
      default:
        return <ScansList />;
    }
  };

  return (
    <div className="app">
      <header className="app-header">
        <h1>Enhanced OWASP ZAP Scanner</h1>
        {apiStatus && (
          <div className="api-status">
            <p>
              API: <span className={`status ${apiStatus.api_status === "running" ? "status-ok" : "status-error"}`}>
                {apiStatus.api_status === "running" ? "Online" : "Offline"}
              </span>
            </p>
            <p>
              ZAP: <span className={`status ${apiStatus.zap_status === "connected" ? "status-ok" : "status-error"}`}>
                {apiStatus.zap_status === "connected" ? "Подключен" : "Отключен"}
              </span>
            </p>
          </div>
        )}
      </header>

      {alertMessage && <Alert type={alertType} message={alertMessage} />}

      {!selectedScan && (
        <div className="tabs">
          <button
            className={`tab ${activeTab === "scans" ? "active" : ""}`}
            onClick={() => setActiveTab("scans")}
          >
            Сканирования
          </button>
          <button
            className={`tab ${activeTab === "new-scan" ? "active" : ""}`}
            onClick={() => setActiveTab("new-scan")}
          >
            Новое сканирование
          </button>
          <button
            className={`tab ${activeTab === "reports" ? "active" : ""}`}
            onClick={() => setActiveTab("reports")}
          >
            Отчеты
          </button>
        </div>
      )}

      <main className="content">
        {renderContent()}
      </main>
    </div>
  );
}

export default App;