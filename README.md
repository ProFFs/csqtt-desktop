# csqtt-desktop

Десктопный клиент [csqtt](https://github.com/amurcanov/csqtt) для Windows и Linux:
обновлённое ядро csqtt **v2.5.0** и собственный графический интерфейс (eframe/egui).

Проект вырос из форка `luminescq/focsq` (мобильная обёртка над csqtt v2.1.9):
ядро синхронизировано с апстримом v2.5.0 (TURN IP-pool, доменная маршрутизация,
SRTP/транспорт-режимы, скалирование туннелей), GUI написан заново и **не**
использует бренд, дизайн или ассеты FOCSQ (лицензия апстрима — PolyForm
Noncommercial, товарные знаки принадлежат их владельцам).

## Возможности

- NAT-обход через TURN-реле (DTLS/SRTP, обфускация, WRAP-ключ из пароля);
- авторизация VK: `vkcalls` (звонки), `auto_js` (токен), `legacy`;
- нативный TUN: Windows — Wintun, Linux — `/dev/net/tun`, настройка IP/DNS/маршрутов ядром;
- доменная маршрутизация (RU-зоны напрямую), исключения хостов VK CDN;
- капча: встроенный солвер + ручная отправка ответа из GUI;
- живые логи и статистика (активные туннели, трафик вверх/вниз).

## Структура

```
backend/   — ядро csqtt v2.5.0, библиотека csqtt-core (TUN, TURN, VK-авторизация)
gui/       — настольное приложение csqtt-desktop (eframe/egui + tokio)
vendor/    — вендорные патчи primp/netstack-smoltcp (в backend/vendor)
domains.txt — базовый список доменов для шаблонной маршрутизации
```

## Сборка

Требуется Rust ≥ 1.97.1 (edition 2024).

```bash
cargo build --release -p csqtt-desktop
```

- **Windows**: рядом с `csqtt-desktop.exe` положите `wintun.dll`
  ([wintun-0.14.1.zip](https://www.wintun.net/builds/wintun-0.14.1.zip), каталог `Junction/bin/x64`);
  запускать от имени администратора (создание TUN-адаптера).
- **Linux**: права `CAP_NET_ADMIN` / доступ к `/dev/net/tun` (root или `setcap`).

Готовые Windows-сборки: вкладка **Actions** → workflow *build-windows* → артефакт `csqtt-desktop-win64`.

## Использование

1. Вкладка «Подключение»: TURN-хост, порт, пир (`host:port`), хеши VK, пароль.
2. «Подключиться» — ядро само создаст TUN-адаптер и поднимет туннели.
3. «Логи» — вывод ядра и события; «Настройки» — туннели, обфускация, капча, доменная маршрутизация.
4. Конфиг хранится в `%APPDATA%/csqtt-desktop/config.json` (пароль — по желанию).

## Лицензия

PolyForm Noncommercial 1.0.0 (см. `LICENSE`) — наследуется от ядра csqtt;
использование только в некоммерческих целях.