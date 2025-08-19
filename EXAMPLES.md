# LanCalc - Примеры использования оптимизированных возможностей

## Новые возможности

### 1. Дебаг режим

#### CLI с дебаг информацией:
```bash
# Включить дебаг режим
lancalc 192.168.1.1/24 --debug

# С JSON выводом и дебаг информацией
lancalc 192.168.1.1/24 --json --debug

# Асинхронный режим с дебаг
lancalc 192.168.1.1/24 --async-mode --debug
```

#### GUI с дебаг режимом:
```bash
# Запуск GUI с дебаг режимом
lancalc --debug
```

### 2. Кэширование

#### Просмотр статистики кэша:
```bash
# Показать статистику кэша
lancalc --cache-stats

# В JSON формате
lancalc --cache-stats --json
```

#### Очистка кэша:
```bash
# Очистить кэш
lancalc --clear-cache
```

### 3. Асинхронные операции

#### CLI асинхронный режим:
```bash
# Использовать асинхронные вычисления
lancalc 192.168.1.1/24 --async-mode

# С дебаг информацией
lancalc 192.168.1.1/24 --async-mode --debug
```

### 4. Расширенная информация о сети

#### Получение внутреннего IP:
```bash
# Показать внутренний IP
lancalc --internal

# С дебаг информацией
lancalc --internal --debug
```

#### Получение внешнего IP:
```bash
# Показать внешний IP
lancalc --external

# С дебаг информацией
lancalc --external --debug
```

#### Комбинированная информация:
```bash
# Показать и внутренний, и внешний IP
lancalc --internal --external --debug
```

## Примеры вывода

### Дебаг режим CLI:
```
⏱️  Computation time: 2.345ms
📋 Cache hit: false

Network: 192.168.1.0
Prefix: /24
Netmask: 255.255.255.0
Broadcast: 192.168.1.255
Hostmin: 192.168.1.1
Hostmax: 192.168.1.254
Hosts: 254
```

### JSON с дебаг информацией:
```json
{
  "network": "192.168.1.0",
  "prefix": "/24",
  "netmask": "255.255.255.0",
  "broadcast": "192.168.1.255",
  "hostmin": "192.168.1.1",
  "hostmax": "192.168.1.254",
  "hosts": "254",
  "_timing": {
    "computation_time": 2.345,
    "cache_hit": false,
    "cache_stats": {
      "size": 5,
      "enabled": true,
      "max_workers": 4
    }
  }
}
```

### Статистика кэша:
```
Cache Statistics:
  Size: 15
  Enabled: true
  Max Workers: 4
```

## Программное использование

### Синхронные операции:
```python
from lancalc import core

# Обычное вычисление
result = core.compute("192.168.1.1", 24)

# С дебаг режимом
core.setup_logging(debug=True)
result = core.compute("192.168.1.1", 24)
```

### Асинхронные операции:
```python
import asyncio
from lancalc import core

async def main():
    # Асинхронное вычисление
    result = await core.compute_async("192.168.1.1", 24)
    
    # Асинхронное вычисление из CIDR
    result = await core.compute_from_cidr_async("192.168.1.1/24")

asyncio.run(main())
```

### Работа с кэшем:
```python
from lancalc import core

# Получить статистику кэша
stats = core.get_cache_stats()
print(f"Cache size: {stats['size']}")

# Очистить кэш
core.clear_cache()
```

### Сетевые адаптеры:
```python
from lancalc import adapters

# Синхронные операции
internal_ip = adapters.get_internal_ip()
external_ip = adapters.get_external_ip()
cidr = adapters.get_cidr(internal_ip)

# Асинхронные операции
async def get_network_info():
    internal_ip = await adapters.get_internal_ip_async()
    external_ip = await adapters.get_external_ip_async()
    cidr = await adapters.get_cidr_async(internal_ip)
    return internal_ip, external_ip, cidr

# Полная информация о сети
network_info = adapters.get_network_info()
connectivity = adapters.validate_network_connectivity()
```

## Оптимизации производительности

### 1. Кэширование результатов
- Автоматическое кэширование вычислений
- Ограничение размера кэша (1000 записей)
- FIFO политика очистки

### 2. Асинхронные операции
- ThreadPoolExecutor для тяжелых вычислений
- Неблокирующие сетевые операции
- Улучшенная отзывчивость GUI

### 3. Оптимизированное логирование
- Условное логирование (только в дебаг режиме)
- Измерение времени выполнения
- Детальная информация о кэше

### 4. Улучшенная обработка ошибок
- Graceful fallbacks для сетевых операций
- Детальные сообщения об ошибках
- Восстановление после сбоев

## Совместимость

Все новые возможности обратно совместимы с существующим кодом:
- Старые вызовы функций работают без изменений
- Новые параметры опциональны
- Дебаг режим по умолчанию отключен
- Кэширование включено по умолчанию