#!/bin/bash

# Настройки подключения
HOST="http://localhost:8000"
FROM="SVO"
TO="OVB"
CLASS="Economy"
MAX_CONN="3"

echo "=== СТАРТ СКАНИРОВАНИЯ 2025 ГОДА ==="
echo "Ищем маршруты $FROM -> $TO ($CLASS, пересадок: $MAX_CONN)..."

# Цикл по дням года (от 0 до 364)
for i in {0..364}; do
    # Генерируем дату для 2025 года, прибавляя i дней к 1 января
    CURRENT_DATE=$(date -d "2025-01-01 + $i days" +%Y-%m-%d 2>/dev/null)
    
    # Если на Mac OS (BSD date) предыдущая команда вернула ошибку, используем синтаксис для Mac:
    if [ -z "$CURRENT_DATE" ]; then
        CURRENT_DATE=$(date -j -v+${i}d -f "%Y-%m-%d" "2025-01-01" "+%Y-%m-%d" 2>/dev/null)
    fi

    # Делаем запрос к твоему API
    # -s глушит прогресс-бар curl
    RESPONSE=$(curl -s "$HOST/routes?from=$FROM&to=$TO&departure_date=$CURRENT_DATE&booking_class=$CLASS&max_connections=$MAX_CONN")

    # Проверяем ответ: если он пустой, равен [] или содержит ошибку, то идем дальше
    if [ "$RESPONSE" != "[]" ] && [ ! -z "$RESPONSE" ]; then
        echo -e "\n[БИНГО] Найдена живая дата: $CURRENT_DATE"
        echo "Ответ сервера:"
        echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
    else
        # Просто выводим точку в строке, чтобы видеть, что скрипт не завис
        printf "."
    fi
done

echo -e "\n=== СКАНИРОВАНИЕ ЗАВЕРШЕНО ==="