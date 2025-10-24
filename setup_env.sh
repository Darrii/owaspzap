#!/bin/bash
# Скрипт для настройки виртуальной среды и установки зависимостей

# Создание виртуальной среды
echo "Создание виртуальной среды zapenv..."
python -m venv zapenv

# Активация виртуальной среды
echo "Активация виртуальной среды..."
source zapenv/bin/activate

# Обновление pip
echo "Обновление pip..."
pip install --upgrade pip

# Установка зависимостей
echo "Установка зависимостей из requirements.txt..."
pip install -r requirements.txt

echo "Настройка виртуальной среды успешно завершена."
echo "Для активации виртуальной среды используйте команду:"
echo "source zapenv/bin/activate"