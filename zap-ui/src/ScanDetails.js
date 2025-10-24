import React from 'react';

// Component for displaying scan details
const ScanDetails = ({ scan, onBack }) => {
  // Helper function to safely render alerts
  const renderAlerts = (alerts) => {
    if (!alerts || !Array.isArray(alerts) || alerts.length === 0) {
      return <p>Нет доступных оповещений.</p>;
    }

    return (
      <div className="alerts-list">
        <h4 className="text-lg font-semibold mb-2">Найденные уязвимости ({alerts.length})</h4>
        <table>
          <thead>
            <tr>
              <th>Тип</th>
              <th>Риск</th>
              <th>URL</th>
              <th>Параметр</th>
              <th>CVSS</th>
            </tr>
          </thead>
          <tbody>
            {alerts.slice(0, 20).map((alert, index) => (
              <tr key={index}>
                <td>{alert.name || alert.alert || "Неизвестно"}</td>
                <td>
                  <span className={`risk risk-${(alert.risk || "").toLowerCase()}`}>
                    {alert.risk || alert.riskdesc || "Неизвестно"}
                  </span>
                </td>
                <td>
                  {alert.url ? (
                    <a href={alert.url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                      {alert.url.replace(/^https?:\/\//, '').substring(0, 30)}
                      {alert.url.length > 30 ? '...' : ''}
                    </a>
                  ) : "Н/Д"}
                </td>
                <td>{alert.param || "Н/Д"}</td>
                <td>{alert.cvss_base_score || alert.base_score || "Н/Д"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {alerts.length > 20 && (
          <div className="alerts-more">
            Показано 20 из {alerts.length} уязвимостей
          </div>
        )}
      </div>
    );
  };

  // Function to render scan summary if available
  const renderSummary = () => {
    if (!scan.summary) return null;
    
    return (
      <div className="card">
        <h3>Сводка</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p><strong>Всего оповещений:</strong> {scan.summary.total_alerts || 0}</p>
            <p><strong>После анализа:</strong> {scan.summary.analyzed_alerts || 0}</p>
            <p><strong>Сокращение ложных срабатываний:</strong> {scan.summary.false_positives_reduction?.toFixed(2) || 0}%</p>
          </div>
          <div>
            <p><strong>Распределение рисков:</strong></p>
            <div className="risk-summary mt-2">
              <span className="risk-critical">{scan.summary.risk_summary?.critical || 0}</span>
              <span className="risk-high">{scan.summary.risk_summary?.high || 0}</span>
              <span className="risk-medium">{scan.summary.risk_summary?.medium || 0}</span>
              <span className="risk-low">{scan.summary.risk_summary?.low || 0}</span>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Function to render remediation guide if available
  const renderRemediationGuide = () => {
    if (!scan.remediation_guide) return null;
    
    const { critical, high, medium, low } = scan.remediation_guide;
    const hasGuide = critical.length > 0 || high.length > 0 || medium.length > 0 || low.length > 0;
    
    if (!hasGuide) return null;
    
    return (
      <div className="card">
        <h3>Руководство по устранению уязвимостей</h3>
        
        {critical.length > 0 && (
          <div className="mb-4">
            <h4 className="text-lg font-semibold text-red-700 mb-2">Критичные ({critical.length})</h4>
            <ul className="list-disc pl-5">
              {critical.map((vuln, i) => (
                <li key={i} className="mb-2">
                  <strong>{vuln.alert_name}</strong> ({vuln.instance_count} экземпляров)
                  <p className="text-sm">{vuln.solution?.substring(0, 150)}{vuln.solution?.length > 150 ? '...' : ''}</p>
                </li>
              ))}
            </ul>
          </div>
        )}
        
        {high.length > 0 && (
          <div className="mb-4">
            <h4 className="text-lg font-semibold text-orange-600 mb-2">Высокие ({high.length})</h4>
            <ul className="list-disc pl-5">
              {high.map((vuln, i) => (
                <li key={i} className="mb-2">
                  <strong>{vuln.alert_name}</strong> ({vuln.instance_count} экземпляров)
                  <p className="text-sm">{vuln.solution?.substring(0, 150)}{vuln.solution?.length > 150 ? '...' : ''}</p>
                </li>
              ))}
            </ul>
          </div>
        )}
        
        {medium.length > 0 && medium.slice(0, 3).length > 0 && (
          <div className="mb-4">
            <h4 className="text-lg font-semibold text-yellow-600 mb-2">Средние (показаны {Math.min(medium.length, 3)} из {medium.length})</h4>
            <ul className="list-disc pl-5">
              {medium.slice(0, 3).map((vuln, i) => (
                <li key={i} className="mb-2">
                  <strong>{vuln.alert_name}</strong> ({vuln.instance_count} экземпляров)
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  };

  // Main renderer
  return (
    <div className="scan-details">
      <div className="scan-details-header">
        <h2 className="text-2xl font-bold">
          Детали сканирования
          {scan.target_url && (
            <>: <span className="text-blue-600">{scan.target_url}</span></>
          )}
        </h2>
        <button
          onClick={onBack}
          className="btn btn-secondary"
        >
          Назад
        </button>
      </div>

      {scan.error ? (
        <div className="card error-card">
          <h3>Ошибка</h3>
          <p className="error-message">{scan.error}</p>
        </div>
      ) : (
        <>
          {/* Basic scan information */}
          <div className="scan-info">
            <div className="card">
              <h3>Информация о сканировании</h3>
              <div className="grid grid-cols-2 gap-2">
                <p><strong>ID:</strong> {scan.id || 'Н/Д'}</p>
                <p><strong>Профиль:</strong> {scan.profile || 'Н/Д'}</p>
                <p><strong>Статус:</strong> <span className={`status status-${scan.status}`}>{scan.status || 'Н/Д'}</span></p>
                <p><strong>Создано:</strong> {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Н/Д'}</p>
                <p><strong>Обновлено:</strong> {scan.updated_at ? new Date(scan.updated_at).toLocaleString() : 'Н/Д'}</p>
                <p><strong>Время сканирования:</strong> {scan.scan_time ? `${scan.scan_time.toFixed(2)} сек` : 'Н/Д'}</p>
              </div>
            </div>
            
            {/* Render summary if available */}
            {renderSummary()}
          </div>
          
          {/* Remediation Guide */}
          {renderRemediationGuide()}
          
          {/* Alerts list */}
          <div className="card">
            {renderAlerts(scan.alerts)}
          </div>
          
          {/* Analysis metrics if available */}
          {scan.analysis_metrics && (
            <div className="card">
              <h3>Метрики анализа</h3>
              <p><strong>Изначальное количество оповещений:</strong> {scan.analysis_metrics.original_count}</p>
              <p><strong>После фильтрации:</strong> {scan.analysis_metrics.filtered_count}</p>
              <p><strong>Выявлено ложных срабатываний:</strong> {scan.analysis_metrics.identified_false_positives || 0}</p>
              <p><strong>Итоговое количество оповещений:</strong> {scan.analysis_metrics.final_count}</p>
              <p><strong>Сокращение ложных срабатываний:</strong> {scan.analysis_metrics.reduction_percentage?.toFixed(2) || 0}%</p>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default ScanDetails;