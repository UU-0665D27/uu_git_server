# uu-git-server

Лёгкий self-hosted Git-сервер на Rust с поддержкой **HTTP(S) Smart Protocol** и **SSH**, песочницей для git-процессов (Landlock + seccomp) и простой файловой системой пользователей.

## Возможности

- 🔀 **Два транспорта одновременно**: HTTP (`git clone https://...`) и SSH (`git clone ssh://...`), оба слушаются в одном процессе.
- 🔑 **Аутентификация**:
  - HTTP — Basic Auth, пароли хранятся как Argon2-хеши.
  - SSH — публичные ключи (формат OpenSSH), плюс встроенный пользователь `public` для анонимного чтения.
- 📁 **Модель репозиториев**: путь вида `owner/repo` (ровно два сегмента).
  Репозиторий создаётся автоматически как bare **только при первом `push`**.
  `fetch`/`clone`/`pull` на несуществующий репозиторий возвращают ошибку
  (`404 Not Found` по HTTP, `ERR Repository not found` по SSH),
  а не пустой репозиторий.
- 🔒 **Приватные/публичные репозитории**: метаданные хранятся в файле `.repo-config` в каждом репозитории.
  - По умолчанию все репозитории **публичные** (доступны всем аутентифицированным пользователям).
  - **Приватные репозитории** доступны только владельцу и приглашённым коллаборантам.
  - Управление видимостью и коллаборантами через REST API: `POST /api/repo/:owner/:repo/visibility`, `POST /api/repo/:owner/:repo/collaborators`, `DELETE /api/repo/:owner/:repo/collaborators/:username`.
- 🚫 **Контроль доступа на запись**: `git push` разрешён только владельцу репозитория (сегмент `owner` в пути должен совпадать с именем аутентифицированного пользователя).
- 🛡 **Песочница для git-процесса**: каждый вызов `git upload-pack` / `git receive-pack` запускается под **Landlock** (ограничение файловой системы только нужными путями) и **seccomp** (белый список системных вызовов).
- ⚙️ **Конфигурация через `config.toml`** с автогенерацией дефолтного файла при первом запуске.
- 🖥️ **Веб-интерфейс (GUI)**: дашборд с отфильтрованным списком доступных репозиториев для каждого пользователя.

## Архитектура

```
main.rs            — точка входа, запускает HTTP- и SSH-сервер параллельно (tokio::select!)
config.rs          — загрузка/создание config.toml
auth.rs            — модель User, проверка пароля (Argon2) и SSH-ключей, Basic Auth extractor
repo_meta.rs       — управление метаданными репозиториев (.repo-config), видимость и коллаборанты
git/
  ensure_bare_repo.rs — создание bare-репозитория, если его нет
  check_bare.rs       — проверка/переинициализация репозитория как bare
web/
  mod.rs            — HTTP-обработчик Smart HTTP Protocol (info/refs, upload-pack, receive-pack)
                       + проверка доступа к приватным репозиториям
  handshake.rs      — обработка GET .../info/refs (анонс рефов)
  gitseccomp.rs     — seccomp-профиль для HTTP-ветки
  gui/
    mod.rs          — веб-интерфейс (дашборд, управление видимостью репозиториев)
    repos.rs        — сканирование репозиториев с фильтрацией по доступу
    session_store.rs — хранилище сессий (SQLite)
    templates.rs    — шаблоны HTML (Askama)
ssh.rs              — SSH-сервер на russh: аутентификация по ключу, exec git-upload-pack/git-receive-pack,
                       Landlock + seccomp для дочернего процесса git
examples/
  gen_user.rs        — CLI-утилита для создания пользователя (username + password → users/<username>.json)
```

## Установка и запуск

```bash
git clone <this-repo>
cd uu-git-server
cargo build --release
./target/release/uu-git-server
```

При первом запуске, если файл конфигурации не найден, будет создан `config.toml` в текущей директории со значениями по умолчанию, а также сгенерирован SSH host-ключ `ssh_host_ed25519_key`.

### Конфигурация (`config.toml`)

| Поле          | По умолчанию         | Описание                                  |
|---------------|----------------------|--------------------------------------------|
| `repos_base`  | `/tmp/git-server`    | Корневая директория для bare-репозиториев |
| `users_dir`   | `./users`            | Директория с JSON-файлами пользователей   |
| `host`        | `127.0.0.1`          | Адрес для HTTP-сервера                    |
| `port`        | `8080`               | Порт HTTP-сервера                         |
| `ssh_port`    | `2222`               | Порт SSH-сервера                          |
| `log_level`   | `info`               | Уровень логирования (через `RUST_LOG`/`EnvFilter`) |

Сервер ищет конфиг по путям `./config.toml`, затем `/etc/uu_git_server/config.toml`.

## Управление пользователями

Пользователь — это JSON-файл `<users_dir>/<username>.json`:

```json
{
  "username": "alice",
  "password_hash": "$argon2id$v=19$...",
  "public_keys": [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@laptop"
  ]
}
```

Создать пользователя с паролем (для HTTP) можно через пример `gen_user`:

```bash
# со случайным паролем
cargo run --example gen_user alice

# с заданным паролем
cargo run --example gen_user alice mysecretpassword
```

Утилита выведет пароль в консоль (он больше нигде не сохраняется) и запишет хеш в `users/alice.json`. SSH-ключи (`public_keys`) на данный момент нужно дописывать в JSON-файл вручную.

Специальный пользователь `public` не требует файла — по SSH он всегда аутентифицируется успешно и имеет доступ только на чтение (push от его имени будет отклонён, так как `public` не совпадает с владельцем ни одного репозитория).

## Управление видимостью репозиториев

Каждый репозиторий имеет файл конфигурации `.repo-config` в своём корне:

```toml
visibility = "public"  # или "private"
collaborators = ["bob", "charlie"]
```

По умолчанию новый репозиторий создаётся с видимостью **public** и без коллаборантов.

### API для управления видимостью

Владелец репозитория может управлять видимостью и коллаборантами через REST API (требуется HTTP Basic Auth):

```bash
# Установить репозиторий приватным
curl -X POST http://alice:password@localhost:8080/api/repo/alice/myrepo/visibility \
  -H "Content-Type: application/json" \
  -d '{"visibility": "private"}'

# Добавить коллаборатора
curl -X POST http://alice:password@localhost:8080/api/repo/alice/myrepo/collaborators \
  -H "Content-Type: application/json" \
  -d '{"username": "bob"}'

# Удалить коллаборатора
curl -X DELETE http://alice:password@localhost:8080/api/repo/alice/myrepo/collaborators/bob \
  -H "Content-Type: application/json"
```

Также можно редактировать `.repo-config` в репозитории напрямую (для приватных репозиториев может потребоваться SSH доступ с правами).

## Использование

### По HTTP

```bash
git clone http://alice:mysecretpassword@localhost:8080/alice/myrepo.git
cd myrepo
git push origin main
```

### По SSH

```bash
git clone ssh://git@localhost:2222/alice/myrepo.git
# или анонимно на чтение
git clone ssh://public@localhost:2222/alice/myrepo.git
```

Аутентификация — по ключу, добавленному в `public_keys` пользователя `alice`. Имя репозитория должно быть в формате `owner/repo`, суффикс `.git` опционален.

## Модель безопасности

- **Аутентификация** проверяется до любого обращения к репозиторию (Basic Auth для HTTP, публичный ключ для SSH).
- **Авторизация на чтение**:
  - **Публичные репозитории** доступны всем аутентифицированным пользователям.
  - **Приватные репозитории** доступны только владельцу и коллаборантам; попытка доступа без прав отклоняется (`403 Forbidden` по HTTP).
- **Авторизация на запись**: сравнивается первый сегмент пути (`owner`) с именем аутентифицированного пользователя; при несовпадении `push` отклоняется.
  - По HTTP — `403 Forbidden` с телом `Push access denied: you are not the repository owner`.
  - По SSH — exec-запрос формально принимается (`channel_success`), но выполнение сразу завершается: клиенту отправляется сообщение об ошибке в виде git-протокольного pkt-line (`ERR Push access denied: not the repository owner`) и запрашивается ненулевой exit-код (`exit_status_request`, код `1`), после чего канал закрывается (`eof` + `close`). Это сделано намеренно вместо `channel_failure`, поскольку `channel_failure` рвёт SSH-канал до того, как клиент успевает прочитать текст ошибки, и git показывает лишь общее `exec request failed on channel 0` без подробностей.
- **Изоляция git-процесса**:
  - **Landlock** ограничивает файловый доступ только путём репозитория, системными библиотеками/бинарями (`/usr/bin`, `/usr/lib`, `/usr/lib/git-core` и т.д.) и конфигами git пользователя, под которым запущен сервер.
  - **seccomp** разрешает только явный список системных вызовов, необходимых git; всё остальное завершает процесс (`Action::Errno`).
- **Хранение метаданных репозиториев**: файл `.repo-config` в корне каждого репозитория содержит видимость (public/private) и список коллаборантов в формате TOML.
- Валидация путей репозитория защищает от path traversal (`..`, лишние сегменты, нулевые байты) как в HTTP-, так и в SSH-обработчиках, а также при загрузке пользователя (`username` не может содержать `/` или `\`).

> ⚠️ Landlock требует поддержки со стороны ядра Linux (ABI V9). На системах без Landlock/seccomp запуск дочернего git-процесса завершится ошибкой инициализации песочницы.

## Известные ограничения / TODO

- Нет команды для добавления SSH-ключей через CLI — правка JSON вручную.
- Нет поддержки `git-shell`-подобных ограничений на другие git-команды по SSH, кроме `upload-pack`/`receive-pack`.
- Аутентификация по SSH-сертификатам (`auth_openssh_certificate`) отключена в коде.
- Нет TLS "из коробки" для HTTP — предполагается запуск за reverse-proxy (nginx/Caddy) с TLS-терминацией.
- Управление видимостью репозиториев через веб-интерфейс (сейчас доступно только через REST API).
