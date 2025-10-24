#!/bin/bash
# Скрипт для запуска всех компонентов проекта

# Переменные для управления цветами в консоли
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Starting Enhanced OWASP ZAP Scanner ===${NC}"

# Проверка, запущен ли контейнер ZAP
echo -e "${BLUE}Checking ZAP container...${NC}"
if [ "$(docker ps -q -f name=zap)" ]; then
    echo -e "${GREEN}ZAP container is already running${NC}"
else
    echo -e "${YELLOW}ZAP container is not running${NC}"
    if [ "$(docker ps -aq -f name=zap)" ]; then
        echo -e "${BLUE}Starting existing ZAP container...${NC}"
        docker start zap
    else
        echo -e "${BLUE}Creating and starting new ZAP container...${NC}"
        docker run -d -p 8080:8080 -p 8090:8090 --name zap zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config 'api.key=12345' -config 'api.addrs.addr.name=.*' -config 'api.addrs.addr.regex=true'
    fi
    
    # Проверка, успешно ли запустился контейнер
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}ZAP container started successfully${NC}"
    else
        echo -e "${RED}Failed to start ZAP container${NC}"
        exit 1
    fi
fi

# Проверка, активирована ли виртуальная среда
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo -e "${YELLOW}Virtual environment is not activated${NC}"
    if [ -d "zapenv" ]; then
        echo -e "${BLUE}Activating existing virtual environment...${NC}"
        source zapenv/bin/activate
    else
        echo -e "${BLUE}Creating and activating new virtual environment...${NC}"
        python -m venv zapenv
        source zapenv/bin/activate
        
        echo -e "${BLUE}Installing required packages...${NC}"
        pip install -r requirements.txt
    fi
else
    echo -e "${GREEN}Virtual environment is already activated: $VIRTUAL_ENV${NC}"
fi

# Создание директорий для хранения данных
echo -e "${BLUE}Creating data directories...${NC}"
mkdir -p reports scans models static

# Копирование файла index.html в директорию static
echo -e "${BLUE}Copying index.html to static directory...${NC}"
if [ -f "index.html" ]; then
    cp index.html static/index.html
    echo -e "${GREEN}File index.html copied successfully${NC}"
else
    echo -e "${RED}File index.html not found!${NC}"
    exit 1
fi

# Запуск FastAPI сервера в фоновом режиме
echo -e "${BLUE}Starting FastAPI server...${NC}"
python api.py &
API_PID=$!

# Ожидание запуска сервера
echo -e "${BLUE}Waiting for server to start...${NC}"
sleep 3

# Проверка, что сервер запущен
if kill -0 $API_PID 2>/dev/null; then
    echo -e "${GREEN}FastAPI server started successfully (PID: $API_PID)${NC}"
else
    echo -e "${RED}Failed to start FastAPI server${NC}"
    exit 1
fi

# Запуск простого HTTP-сервера для веб-интерфейса
echo -e "${BLUE}Starting web interface (HTTP server)...${NC}"
cd static
python -m http.server 8888 &
UI_PID=$!

echo -e "${GREEN}Web interface started successfully (PID: $UI_PID)${NC}"
echo -e "${GREEN}=== Enhanced OWASP ZAP Scanner is running ===${NC}"
echo -e "${GREEN}API server: http://localhost:8000${NC}"
echo -e "${GREEN}Web interface: http://localhost:8888${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop all services${NC}"

# Ожидание сигнала завершения
trap 'echo -e "${BLUE}Stopping services...${NC}"; kill $API_PID; kill $UI_PID; echo -e "${GREEN}Services stopped${NC}"; exit 0' INT

# Бесконечный цикл для поддержания скрипта активным
while true; do
    sleep 1
done