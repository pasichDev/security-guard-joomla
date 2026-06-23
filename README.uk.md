# Security Guard for Joomla

[![CI](https://github.com/pasichDev/security-guard-joomla/actions/workflows/ci.yml/badge.svg)](https://github.com/pasichDev/security-guard-joomla/actions/workflows/ci.yml)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![Joomla 3.10](https://img.shields.io/badge/Joomla-3.10-5091cd.svg)](https://www.joomla.org/)

[English](README.md) · **Українська**

Повноцінний веб-фаєрвол (WAF) для **Joomla 3.10** — постачається як єдиний інсталяційний
пакет, що містить компонент адмінки та системний плагін.

## Можливості

- 🛡️ **WAF** — фільтрація запитів і блокування за правилами
- 🍯 **Honeypot** — пастка для виявлення шкідливих ботів
- 📊 **Поведінковий скоринг** — оцінка ризику для кожного відвідувача
- 📈 **Жива панель** + монітор трафіку в стилі **Grafana**
- 🌊 **Виявлення DDoS**
- 🌍 **Гео-трекінг** запитів
- 🇬🇧 🇺🇦 Англійська та українська локалізації

## Встановлення

1. Завантажте `pkg_securityguard-<версія>.zip` з
   [останнього релізу](https://github.com/pasichDev/security-guard-joomla/releases/latest).
2. В адмінці Joomla: **Система → Встановити → Розширення → Завантажити файл пакета**.
3. Завантажте пакет — компонент і системний плагін встановлюються разом.
4. Увімкніть плагін **System – Security Guard** у **Розширення → Плагіни**.

Після встановлення Joomla перевіряє сервер оновлень цього репозиторію й автоматично
пропонує оновлення прямо в адмінці.

## Збірка з вихідного коду

Чистий PHP — без компіляції. Збірка пакує вихідний код із `src/` в інсталяційні zip-и.

```bash
bash build/build.sh
```

Результат у `dist/`:

| Артефакт | Вміст |
| --- | --- |
| `pkg_securityguard-<версія>.zip` | Повний пакет (встановлюйте його в Joomla) |
| `com_securityguard.zip` | Лише компонент |
| `plg_system_securityguard.zip` | Лише системний плагін |

Скрипт використовує утиліту `zip`, якщо вона є, інакше — Python, тож працює на Linux,
macOS і Windows.

## Структура репозиторію

```
src/                          вихідний код
  com_securityguard/          компонент адмінки
  plg_system_securityguard/   системний плагін
  pkg_securityguard.xml       маніфест пакета (джерело правди для версії)
build/build.sh                скрипт збірки
updates/updates.xml.tmpl      шаблон сервера оновлень Joomla
.github/workflows/            CI (збірка/лінт) та автоматизація релізів
docs/                         документація (англійською)
```

## Релізи та CI

- **CI** перевіряє PHP (`php -l`), валідує XML-маніфести й збирає пакети на кожен push
  та pull request.
- **Реліз** запускається push-ом тегу `vX.Y.Z`: перевіряє відповідність тега й версії в
  маніфесті, збирає zip-и, публікує GitHub Release та оновлює сервер оновлень Joomla на
  GitHub Pages.

## Внесок

Дивіться [docs/](docs/) щодо розробки та релізів. Issues та pull request-и вітаються.

## Ліцензія

[GNU GPL v2 or later](LICENSE) © pasichDev
