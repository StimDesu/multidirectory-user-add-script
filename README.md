# AD -> MultiDirectory: перенос и синхронизация пользователей

Черновой набор скриптов для выгрузки пользователей из Microsoft Active
Directory и создания таких же учёток в [MultiDirectory](https://github.com/MultiDirectoryLab)
(MD) — AD-совместимом каталоге под Linux. Работает через:

- **AD** — обычный LDAP/LDAPS (библиотека `ldap3`), на чтение;
- **MD** — REST API, описанный в `openapi.json` (эндпоинты `/entry/*`), на запись.

> Это набросок для ревью, а не готовое production-решение. Перед боевым
> использованием обязательно прогоните на тестовом AD и тестовом инстансе
> MD — см. раздел «Что стоит проверить перед продакшеном» ниже.

## Быстрый старт (без флагов и конфигов вручную)

Самый простой способ — запустить скрипт совсем без параметров:

```bash
pip install -r requirements.txt
python ad_md_sync.py
```

Откроется интерактивное меню:

1. **При первом запуске** (если `config.yaml` ещё не существует) скрипт сам
   спросит адрес контроллера AD, DN и пароль служебной учётки для чтения
   AD, базовый URL REST API MultiDirectory, логин и пароль служебной учётки
   MD, base DN обоих доменов — и сохранит ответы в `config.yaml` (пункт
   меню «4» вызывает этот же мастер повторно, если нужно всё переввести).
2. Дальше меню предложит **выбрать OU** из списка, который оно само
   получит из AD (не нужно руками собирать DN), и действие: перенос
   (`migrate`) или синхронизация (`sync`, разово или по интервалу).

Меню — это просто удобная обёртка над теми же командами `migrate`/`sync`
(см. ниже); для cron/systemd их по-прежнему можно вызывать напрямую с
флагами, без меню.

### Куда именно указывать адреса AD/MD и учётные записи

Всё это — поля файла **`config.yaml`** (мастер из меню создаёт его за вас;
вручную — скопируйте `config.example.yaml` и заполните):

```yaml
source_ad:                          # <-- откуда переносим (Microsoft AD)
  server: "ldaps://dc1.corp.example.local"   # адрес контроллера домена
  bind_dn: "CN=svc-md-sync,OU=Service Accounts,DC=corp,DC=example,DC=local"
  password: "..."                            # пароль этой учётки в AD
  base_dn: "DC=corp,DC=example,DC=local"     # base DN домена AD

target_md:                          # <-- куда переносим (MultiDirectory)
  base_url: "https://md.corp.example.local/api"  # REST API MD
  username: "svc-md-sync"                        # логин учётки в MD
  password: "..."                                # пароль этой учётки в MD
  base_dn: "DC=md,DC=example,DC=local"           # base DN домена MD
```

Обеим служебным учёткам (`source_ad.bind_dn` — в AD, `target_md.username` —
в MD) нужны соответствующие права: на чтение в AD и на создание/изменение
объектов в целевых OU в MD.

Пароли можно не хранить в файле, а передать через переменные окружения —
они имеют приоритет над значениями из `config.yaml`:

```bash
export AD_BIND_PASSWORD='...'
export MD_BIND_PASSWORD='...'
python ad_md_sync.py
```

## Возможности

- **`migrate`** — разовый перенос: создаёт в MD структуру OU и пользователей
  из выбранных OU в AD (или из всего домена, если OU не заданы).
- **`sync`** — сравнивает текущее состояние AD с ранее сохранённым
  состоянием (`state.json`) и:
  - создаёт новых пользователей;
  - **переименовывает** учётку, если изменился CN;
  - **перемещает** учётку между OU, если сменился путь в AD (используется
    `ModifyDN` через `/entry/update_many/dn`, одним вызовом меняются и RDN,
    и родительский контейнер);
  - обновляет изменившиеся атрибуты (`ФИО`, `email`, `телефон` и т.п.);
  - **выключает** учётку в MD, если она отключена в AD (`userAccountControl`
    бит `ACCOUNTDISABLE`), и включает обратно, если снова активна;
  - по выбору (`on_missing_in_ad`) блокирует, удаляет или игнорирует
    учётки в MD, чьи оригиналы пропали из выбранных OU в AD (удалены,
    перемещены за пределы отслеживаемой области и т.п.).

## Файлы

| Файл | Назначение |
|---|---|
| `ad_md_sync.py` | CLI-точка входа (`menu` по умолчанию, `migrate`, `sync`) |
| `ad_source.py` | чтение пользователей/OU из AD через `ldap3` |
| `md_client.py` | клиент REST API MultiDirectory |
| `dn_utils.py` | перенос DN между базами (`DC=corp,...` → `DC=md,...`) |
| `state_store.py` | хранение состояния синхронизации между запусками |
| `config.example.yaml` | шаблон конфигурации |

## Установка

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml
# отредактируйте config.yaml под ваш домен
```

Пароли сервисных учёток можно не хранить в файле, а передавать через
переменные окружения — они переопределяют значения из `config.yaml`:

```bash
export AD_BIND_PASSWORD='...'
export MD_BIND_PASSWORD='...'
```

### Сервисные учётные записи

- **AD**: учётная запись с правом чтения нужных OU (обычного read-доступа
  членов домена достаточно для чтения атрибутов пользователей).
- **MD**: учётная запись с правами на создание/изменение/перемещение
  объектов в целевых OU (без MFA — см. ограничения ниже).

## Использование

Для интерактивной работы достаточно `python ad_md_sync.py` (см. «Быстрый
старт» выше). Ниже — то же самое, но напрямую флагами командной строки,
без меню (для скриптов, cron, systemd).

Разовый перенос выбранных OU (структура + пользователи):

```bash
python ad_md_sync.py --config config.yaml migrate \
    --ou "OU=Moscow,OU=Users,DC=corp,DC=example,DC=local" \
    --ou "OU=SPB,OU=Users,DC=corp,DC=example,DC=local"
```

Если `--ou` не указан, используется список `organizational_units` из
`config.yaml`, а если и он пуст — весь `source_ad.base_dn`.

Проверка "что будет сделано" без реальных изменений:

```bash
python ad_md_sync.py --config config.yaml migrate --dry-run -v
```

Синхронизация (разовый проход, для cron/systemd timer):

```bash
python ad_md_sync.py --config config.yaml sync
```

Синхронизация в режиме демона (для теста/небольших инсталляций; для
продакшена лучше `cron`/`systemd timer` + `--once`, это надёжнее переживает
перезапуски и падения):

```bash
python ad_md_sync.py --config config.yaml sync --interval 300
```

### Пример systemd timer

```ini
# /etc/systemd/system/ad-md-sync.service
[Unit]
Description=AD -> MultiDirectory sync

[Service]
Type=oneshot
WorkingDirectory=/opt/ad-md-sync
Environment=AD_BIND_PASSWORD=...
Environment=MD_BIND_PASSWORD=...
ExecStart=/opt/ad-md-sync/.venv/bin/python ad_md_sync.py --config config.yaml sync
```

```ini
# /etc/systemd/system/ad-md-sync.timer
[Unit]
Description=Run AD -> MultiDirectory sync every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

## Как это устроено

- Соответствие пользователей хранится по `objectGUID` в `state.json`
  (путь задаётся `sync.state_file`), а не по DN — поэтому переименование
  и перенос между OU определяются надёжно, даже если поменялись оба сразу.
- DN в MD строится заменой суффикса базового DN: всё, что "перед"
  `source_ad.base_dn` в DN AD-объекта, переносится как есть перед
  `target_md.base_dn` (см. `dn_utils.map_dn`). Т.е. цепочка `OU=...`
  должна называться одинаково в обоих каталогах — при `migrate`/`sync`
  недостающие OU создаются автоматически.
- Новым пользователям в MD выставляется случайный пароль (пароли из AD
  прочитать нельзя — там хранится только хэш). Пароли новых учёток можно
  записывать в CSV (`sync.password_log_file`) для последующей выдачи
  пользователям — **файл содержит пароли в открытом виде, храните и
  удаляйте его соответствующим образом**.
- "Выключение" учётки реализовано через `/entry/status`
  (`LockoutStatus`) — это единственный явно описанный в `openapi.json`
  способ блокировки учётки. Возможно, в вашей версии MD это скорее
  "lockout", чем полноценный AD-style disable — см. пункт ниже.

## Что стоит проверить перед продакшеном

Скрипт написан по `openapi.json` без доступа к живому инстансу MD,
поэтому несколько мест нуждаются в проверке на вашем стенде:

1. **Семантика `/entry/status`.** В спеке это "Set status for a
   directory" с `LockoutStatus` (0/1). Скрипт трактует `1` как
   "заблокировано/выключено". Проверьте, что это действительно
   аналог `ACCOUNTDISABLE`, а не что-то вроде временной блокировки после
   неудачных попыток входа.
2. **Обязательные атрибуты пользователя.** Список `object_classes` и
   `attribute_names` в конфиге — стандартный AD-набор
   (`top/person/organizationalPerson/user`, `sAMAccountName`,
   `userPrincipalName` и т.д.). Если схема вашего MD требует других
   обязательных атрибутов — посмотрите `GET /schema/entity_type/user`
   на живом сервере и дополните `build_user_attributes()` в
   `ad_md_sync.py`.
3. **MFA у сервисной учётки MD.** `MDClient.login()` явно отказывает,
   если сервер в ответ на логин присылает MFA-челлендж — доработайте
   под ваш MFA-провайдер, если сервисную учётку нельзя завести без MFA.
4. **Группы (`memberOf`).** Текущая версия переносит только сами
   учётки пользователей и структуру OU, без членства в группах. Это
   осознанное упрощение черновика — расширяется отдельной функцией
   по аналогии с `migrate_users`, если понадобится.
5. **Контейнеры вида `CN=Users`.** Скрипт переносит только объекты
   `organizationalUnit`. Если в AD пользователи лежат прямо в
   дефолтном контейнере `CN=Users` (это `container`, а не OU), либо
   заранее создайте соответствующую OU в MD и не указывайте `CN=Users`
   в `organizational_units`, либо доработайте `migrate_ous`.
6. **Права API-пользователя MD** на запись данных, конфигурируемых
   для `/entry/add`, `/entry/update`, `/entry/update_many/dn`,
   `/entry/status`, `/entry/delete` в целевых OU.
7. **Нагрузочный профиль.** `sync` сейчас делает полный обход
   выбранных OU в AD на каждом проходе (без инкрементального фильтра
   по `whenChanged`) — для доменов с десятками тысяч пользователей
   стоит добавить инкрементальную выборку.
