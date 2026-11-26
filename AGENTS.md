# RosPanel Agent Guide & Workspace Invariants

Проект: **WildSpy/rospanel-extended** — форк [Shu1t3/rospanel-shu1t3](https://github.com/Shu1t3/rospanel-shu1t3), который сам является форком панели управления прокси-серверами [AppsGanin/rospanel](https://github.com/AppsGanin/rospanel). Собственные релизы этого репозитория начинаются с 5.12.2.  
Путь Go-модуля намеренно оставлен `github.com/Shu1t3/rospanel-shu1t3` (`go.mod`, импорты, `go_package` в `internal/xray/statsrpc/stats.proto`): это только имя, код собирается из этого репозитория. Не переименовывать без отдельного решения — переименование затрагивает ~740 файлов и ломает слияния с обоими upstream.  
Архитектура: Распределённая система Master-Node.  
Бэкенд: Go 1.27 + CGO-free SQLite (WAL) + интеграция с Xray-core / Sing-box / WireGuard / AmneziaWG.  
Фронтенд: React 19 SPA + Tailwind CSS v4 + Biome + Playwright (`web/`). Встраивается в Go-бинарник через `web/embed.go`.

---

## 1. Release Workflow (Обязательное правило)

Before pushing changes to a branch that triggers a RosPanel release, merging a release PR, or publishing a release by hand, apply the [rospanel-release-lab skill](.agents/skills/rospanel-release-lab/SKILL.md). Complete its Linux checks for the candidate before the first action that can trigger publication. Reuse the evidence for a release PR that only updates version metadata, after checking its diff and base commit. Report any missing coverage and stop publication until the checks pass or the user explicitly accepts the identified gap.

Особенности релизов этого репозитория:
- Версию поднимает только release-please по Conventional Commits в `main` (`feat` → minor, `fix` → patch); `internal/version/version.go`, `docs/openapi.json` и `.release-please-manifest.json` вручную не правятся. Merge release PR публикует GitHub Release, бинарники `rospanel-linux-{amd64,arm64}` с `SHA256SUMS` и образ `ghcr.io/wildspy/rospanel-extended`.
- После push в `main` release-please сам создаёт и обновляет release PR — перед локальной сборкой или новой работой подтягивать `origin/main`, иначе бинарник получит устаревший номер версии.
- Базой для `./scripts/release-lab.sh` брать предыдущий релиз этого форка: `BASELINE_IMAGE=ghcr.io/wildspy/rospanel-extended:<предыдущая версия>` (значение по умолчанию в скрипте указывает на образ Shu1t3).
- Самообновление ставит только строго более новую версию: локальная сборка с тем же номером, что и опубликованный релиз, не перезаписывается до следующего релиза.

---

## 2. Ключевые инварианты проекта

1. **Защита форка (Fork Safeguards)**:
   - Неприкосновенны уникальные подсистемы форка:
     * **Мульти-хоп маршрутизация**: сквозные VLESS цепочки (вход → транзит → выход), редактор `web/src/MultiHopDialog.tsx`, выделенный диапазон портов `28443–28506`, обратные маршруты (`manager_multihop_reverse.go`, `reverse_guard.go`), возвращение на входную ноду.
     * **Лимиты устройств**: отслеживание сессий (`ActiveDeviceCountForUser`), ротация токенов подписки, принудительное завершение соединений.
     * **REALITY & Decoy**: расширенный пул сайтов-доноров РФ и twin names, совмещение decoy и REALITY на порту 443 по SNI, исключение HTTP/3 рекламирования.
     * **Безопасность и хранилище**: brute-guard на уровне `nftables`, идемпотентная обработка дубликатов колонок в миграциях SQLite, сравнение токенов в константном времени.
     * **Инфраструктура**: переменная окружения `ROSPANEL_REPO` для независимого репозитория обновлений.
     * **Telegram WEB-прокси** и прочие возможности форка WildSpy — см. раздел 3.
   - Подробнее: [.agents/rules/fork-safeguards.md](.agents/rules/fork-safeguards.md). При слияниях с upstream руководствоваться навыком [rospanel-sync-upstream](.agents/skills/rospanel-sync-upstream/SKILL.md). Upstream два: AppsGanin/rospanel (основной код) и Shu1t3/rospanel-shu1t3 (защищённые подсистемы выше); при слиянии из любого сохраняются изменения из раздела 3.

2. **Связка фронтенда и бэкенда**:
   - Фронтенд компилируется в `web/dist` и встраивается в Go-бинарник через `web/embed.go` (`//go:embed all:dist`).
   - При любых изменениях в директории `web/` обязательно выполнить:
     * `npm --prefix web run typecheck`
     * `npm --prefix web run lint`
     * `npm --prefix web run build` (обязательно до компиляции Go или прогона Go-тестов, зависящих от встроенного фронтенда).

3. **Синхронизация мультиязычности (i18n)**:
   - Поддерживаются строго 5 языков: Русский (`ru`), Английский (`en`), Фарси (`fa`), Арабский (`ar`), Китайский (`zh`).
   - Любое изменение текста UI требует обновления **всех 5 файлов** в `web/src/i18n/`.
   - Добавление ошибок/сообщений бэкенда требует обновления **всех 5 файлов** в `internal/i18n/` и запуска кодогенерации `go generate ./internal/i18n/...`.
   - Тесты `callsites_test.go` и `TestCatalogsMatch` проверяют синхронность в CI. Подробнее: [.agents/rules/i18n-synchronization.md](.agents/rules/i18n-synchronization.md).

4. **База данных и SQLite миграции**:
   - База работает в режиме WAL на `modernc.org/sqlite` (single-writer).
   - Запрещено удерживать транзакции во время сетевых запросов или долгих операций ввода-вывода (во избежание lock starvation).
   - Миграции `ALTER TABLE` должны быть строго идемпотентными. Номера миграций назначаются с запасом, чтобы не конфликтовать с апстримом. Подробнее: [.agents/rules/sqlite-and-migrations.md](.agents/rules/sqlite-and-migrations.md).

5. **Генерация конфигураций Xray**:
   - Конфигурации Xray генерируются детерминированно в `internal/xray/`.
   - Выключенные протоколы и фичи (например, REALITY) не должны порождать фантомные или невалидные секции в `config.json`.
   - Для проверки интеграции с Xray используется `RP_XRAY_BIN`. Подробнее: [.agents/rules/xray-and-networking.md](.agents/rules/xray-and-networking.md).

---

## 3. Возможности форка WildSpy/rospanel-extended

Добавлены поверх Shu1t3/rospanel-shu1t3 5.12.1 и защищены так же, как подсистемы из раздела 2.

1. **Telegram WEB-прокси** (`feat(mtproto)`, Telegram Desktop 7.1+, Android, iOS) — рядом с fake-TLS полосой MTProto, без внешних бинарников:
   - Код: `internal/mtproto/web.go` (релей), `webpage.go` (страница-мост), `webcap.go` (капабилити и ссылки), `webframe.go` (кодек кадров), `ws.go` (WebSocket RFC 6455); тесты `web_test.go`, `internal/core/manager_mtproto_web_test.go`.
   - Протокол — Telegram «WEB proxy protocol v1»: tdesktop `docs/web-proxy-plan.md`, telegramdesktop/tproxy-server `PROTOCOL.md`, `ANDROID.md`, `IOS.md`. Капабилити `base64url(HMAC-SHA256(0xdd‖secret, "tdesktop-web-proxy-bridge-v1\n"+host))`; ссылка `tg://webproxy?server=<host>&secret=dd<hex>`, порт 443 неявный. Транспорт страницы (carrier) — WebSocket `/api/v1/ws` с субпротоколом `tproxy-v1.<token>`.
   - Инварианты: мост обслуживается собственным сайтом сервера на :443 перед decoy (`MTProtoWebHandler` в `cmd/rospanel/service.go`, `WebHandler` в `internal/nodeagent/agent.go`); любой запрос без верной капабилити или токена уходит на decoy; капабилити сверяется в константном времени, токены одноразовые и живут 2 минуты; каждый поток идёт через тот же `serve()` и `mtproto-in` Xray под UUID пользователя (статистика, лимиты устройств, скорость, маршрутизация); память ограничена окнами 4 MiB на поток и лимитами carrier; секрет никогда не попадает в страницу.
   - Условия: свой домен сервера (`Settings.OwnName`) и TCP-TLS на 443 (`MTProtoWebCandidate`); у ноды — доверенный сертификат и агент, сообщающий `SyncRequest.MTProtoWeb`. Режим «Только WEB» (`MTProtoWebOnly`) не открывает порт fake TLS.
   - Хранилище и протокол нод: миграция `0160_mtproto_web.sql` (`settings.mtproto_web`, `settings.mtproto_web_only`, `nodes.serves_mtproto_web`); у нод переключатели в `NodeConnections`; `nodeapi.MTProtoState.Web`. UI — карточка MTProto в `web/src/ConnectionsEditor.tsx`; ссылки — `internal/link/mtproto.go`, карточка «· WEB» и QR `/tg/<id>-web.png` на странице подписки.
2. **Источник релизов и самообновления** (`fix(update)`): `internal/updater.Repo = "WildSpy/rospanel-extended"`, `REPO`/`IMAGE` в `install.sh`, команда установки кандидата при переезде мастера через `updateRepo()`; `ROSPANEL_REPO` по-прежнему переопределяет. Ссылки установки в README и `scripts/generate-release-notes.sh` указывают на этот репозиторий.
3. **Переход с AppsGanin/rospanel** (`fix(store)`): `upstreamRenames` в `internal/store/store.go` переносит записи `schema_migrations` upstream (0066..0085) под имена форка (0070..0092) в одной транзакции, чтобы миграции не применялись повторно; тест `internal/store/upstream_migrations_test.go`. Руководство — README, раздел «Переход с AppsGanin/rospanel».
4. **`install.sh --update-node`** (`feat(nodes)`): переводит установленную ноду на агент этого репозитория (проверка SHA256SUMS, `rospanel.prev` для отката, `/var/lib/rospanel-node` не трогается); `GET /api/update` отдаёт `repo`, вкладка «Серверы» показывает команду для нод «новее панели».
5. **Токен `--color-onbrand` в `@theme`** (`web/src/index.css`): без объявления Tailwind v4 не генерирует `bg-onbrand`/`text-onbrand` (бегунок включённого `Switch` сливался с дорожкой). Новые цвета, которые задаёт `brand.tsx` во время работы и используют классы Tailwind, тоже объявлять в `@theme`.

---

## 4. Навигация по правилам и навыкам

- **Точечные правки без лишнего шума**: [.agents/rules/surgical-editing.md](.agents/rules/surgical-editing.md)
- **Дисциплина терминала и проверочные команды**: [.agents/rules/terminal-discipline.md](.agents/rules/terminal-discipline.md)
- **Коммиты и Release-please**: [.agents/rules/changelog-and-commits.md](.agents/rules/changelog-and-commits.md)
- **Идиоматичный Go в контексте RosPanel**: [.agents/rules/go-idiomatic.md](.agents/rules/go-idiomatic.md)
- **Горутины, контексты и блокировки**: [.agents/rules/go-concurrency.md](.agents/rules/go-concurrency.md)
- **Оптимизация токенов и чтение контекста**: [.agents/rules/token-optimization.md](.agents/rules/token-optimization.md)
- **Синхронизация с upstream**: навык [rospanel-sync-upstream](.agents/skills/rospanel-sync-upstream/SKILL.md)
- **Ревью кода перед коммитом**: навык [rospanel-code-review](.agents/skills/rospanel-code-review/SKILL.md)
- **Разработка UI**: навык [rospanel-frontend](.agents/skills/rospanel-frontend/SKILL.md)
- **Отладка Xray**: навык [rospanel-xray-lab](.agents/skills/rospanel-xray-lab/SKILL.md)
- **Оркестрация субагентов**: навык [rospanel-subagents](.agents/skills/rospanel-subagents/SKILL.md)
