import React, { Component } from 'react';

// Компонент для отлова ошибок
class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    // Обновляем состояние с ошибкой
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    // Логируем ошибку в консоль
    console.error("КРИТИЧЕСКАЯ ОШИБКА В КОМПОНЕНТЕ:", error);
    console.error("Информация об ошибке:", errorInfo);
    
    // Выводим полный стек вызовов
    if (error.stack) {
      console.error("Стек вызовов:", error.stack);
    }
    
    // Обновляем состояние
    this.setState({
      error: error,
      errorInfo: errorInfo
    });
  }

  render() {
    if (this.state.hasError) {
      // Рендерим запасной UI
      return (
        <div className="card error-card">
          <h3>Произошла ошибка</h3>
          <p>При отображении компонента произошла ошибка:</p>
          <pre className="error-message">
            {this.state.error && this.state.error.toString()}
          </pre>
          <button 
            className="btn btn-primary"
            onClick={() => this.setState({ hasError: false })}
          >
            Попробовать снова
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;