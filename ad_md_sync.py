#!/usr/bin/env python3
"""
ad_md_sync.py - перенос и синхронизация пользователей из Microsoft AD в MultiDirectory (MD).

Самый простой способ начать -- запустить скрипт вообще без параметров:

    python ad_md_sync.py

Откроется интерактивное меню: при первом запуске оно спросит адреса AD и MD
и служебные учётные записи (и сохранит их в config.yaml), а дальше даст
выбрать нужные OU из списка, полученного прямо из AD, и действие
(перенос / синхронизация), не заставляя вспоминать флаги командной строки.

Команды для запуска без меню (например, из cron / systemd timer):
    menu      Интерактивное меню (используется по умолчанию).
    migrate   Разовый перенос: создать структуру OU и пользователей в MD.
    sync      Сравнить текущее состояние AD с MD и применить изменения
              (создание, переименование/перемещение, изменение атрибутов,
              включение/выключение учёток). Хранит состояние между запусками
              в state-файле, поэтому подходит для регулярного запуска по cron
              / systemd timer.

Примеры:
    python ad_md_sync.py
    python ad_md_sync.py --config config.yaml migrate
    python ad_md_sync.py --config config.yaml migrate --ou "OU=Moscow,OU=Users,DC=corp,DC=local"
    python ad_md_sync.py --config config.yaml sync --dry-run
    python ad_md_sync.py --config config.yaml sync

Скрипт - черновик ("набросок"): перед боевым использованием обязательно
проверьте его на тестовом домене / тестовом инстансе MultiDirectory,
особенно семантику /entry/status (используется как disable/enable учётки)
и набор obligatory-атрибутов, которые ваша схема MD требует для objectClass
"user" (см. /schema/entity_type/user в живом API).
"""

from __future__ import annotations

import argparse
import csv
import getpass
import logging
import os
import re
import secrets
import string
import sys
import time
from dataclasses import asdict
from typing import Any

import yaml

import dn_utils
from ad_source import ADSource, ADUser
from md_client import OP_REPLACE, MDClient, MDError
from state_store import load_state, save_state

logger = logging.getLogger("ad_md_sync")

DEFAULT_ATTRIBUTE_NAMES = {
    "sam": "sAMAccountName",
    "upn": "userPrincipalName",
    "cn": "cn",
    "given_name": "givenName",
    "sn": "sn",
    "display_name": "displayName",
    "mail": "mail",
    "phone": "telephoneNumber",
}

DEFAULT_OBJECT_CLASSES = ["top", "person", "organizationalPerson", "user"]

PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"


# --------------------------------------------------------------------------- #
# Конфигурация
# --------------------------------------------------------------------------- #
def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    # Пароли можно передать через переменные окружения, чтобы не хранить их
    # в конфиге: AD_BIND_PASSWORD и MD_BIND_PASSWORD переопределяют значения
    # из файла, если заданы.
    if os.environ.get("AD_BIND_PASSWORD"):
        cfg["source_ad"]["password"] = os.environ["AD_BIND_PASSWORD"]
    if os.environ.get("MD_BIND_PASSWORD"):
        cfg["target_md"]["password"] = os.environ["MD_BIND_PASSWORD"]

    cfg.setdefault("sync", {})
    cfg["sync"].setdefault("state_file", "./state.json")
    cfg["sync"].setdefault("on_missing_in_ad", "disable")
    cfg["sync"].setdefault("object_classes", DEFAULT_OBJECT_CLASSES)
    cfg["sync"].setdefault("attribute_names", DEFAULT_ATTRIBUTE_NAMES)
    cfg["sync"].setdefault("generated_password_length", 20)
    cfg["sync"].setdefault("password_log_file", "")
    cfg.setdefault("organizational_units", [])
    return cfg


def generate_password(length: int = 20) -> str:
    while True:
        pwd = "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%^&*()-_=+" for c in pwd)
        ):
            return pwd


def log_new_password(path: str, dn: str, sam: str | None, password: str) -> None:
    if not path:
        return
    is_new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow(["dn", "sam", "password"])
        writer.writerow([dn, sam or "", password])


# --------------------------------------------------------------------------- #
# Построение атрибутов пользователя MD из AD-объекта
# --------------------------------------------------------------------------- #
def build_user_attributes(
    user: ADUser, attribute_names: dict[str, str], object_classes: list[str]
) -> dict[str, list[str]]:
    attrs: dict[str, list[str]] = {"objectClass": list(object_classes)}
    field_values = {
        "sam": user.sam,
        "upn": user.upn,
        "cn": user.cn,
        "given_name": user.given_name,
        "sn": user.sn,
        "display_name": user.display_name,
        "mail": user.mail,
        "phone": user.phone,
    }
    for field, value in field_values.items():
        md_attr = attribute_names.get(field)
        if md_attr and value:
            attrs[md_attr] = [value]
    return attrs


def ou_rdn_value(dn: str) -> str:
    """Значение атрибута OU из RDN вида 'OU=Moscow'."""
    rdn = dn_utils.rdn(dn)
    _, _, value = rdn.partition("=")
    return value


# --------------------------------------------------------------------------- #
# migrate: перенос структуры OU
# --------------------------------------------------------------------------- #
def migrate_ous(ad: ADSource, md: MDClient, bases: list[str], ad_base: str, md_base: str, dry_run: bool) -> None:
    ou_dns = list(ad.iter_ou_dns(bases))
    # Создаём от родителей к детям, иначе add_entry для дочерней OU упадёт
    # с NO_SUCH_OBJECT.
    ou_dns.sort(key=dn_utils.depth)
    for ad_ou_dn in ou_dns:
        target_dn = dn_utils.map_dn(ad_ou_dn, ad_base, md_base)
        if md.entry_exists(target_dn):
            logger.debug("OU уже существует в MD: %s", target_dn)
            continue
        logger.info("Создаю OU в MD: %s", target_dn)
        if dry_run:
            continue
        md.add_entry(
            target_dn,
            {"objectClass": ["top", "organizationalUnit"], "ou": [ou_rdn_value(ad_ou_dn)]},
        )


# --------------------------------------------------------------------------- #
# migrate: перенос пользователей (без учёта состояния - только создание)
# --------------------------------------------------------------------------- #
def migrate_users(
    ad: ADSource,
    md: MDClient,
    bases: list[str],
    ad_base: str,
    md_base: str,
    sync_cfg: dict[str, Any],
    state: dict[str, Any],
    dry_run: bool,
) -> None:
    attribute_names = sync_cfg["attribute_names"]
    object_classes = sync_cfg["object_classes"]
    pwd_len = sync_cfg["generated_password_length"]
    pwd_log = sync_cfg["password_log_file"]

    for user in ad.iter_users(bases):
        target_dn = dn_utils.map_dn(user.dn, ad_base, md_base)

        if md.entry_exists(target_dn):
            logger.info("Пользователь уже существует в MD, пропуск: %s", target_dn)
        else:
            attrs = build_user_attributes(user, attribute_names, object_classes)
            password = generate_password(pwd_len)
            logger.info("Создаю пользователя в MD: %s (%s)", target_dn, user.sam)
            if not dry_run:
                md.add_entry(target_dn, attrs, password=password)
                log_new_password(pwd_log, target_dn, user.sam, password)
                if not user.enabled:
                    md.set_status(target_dn, locked=True)

        # Запоминаем соответствие для последующего sync-режима в любом
        # случае (даже если запись уже была создана кем-то другим ранее).
        state["users"][user.guid] = {
            "ad_dn": user.dn,
            "md_dn": target_dn,
            "sam": user.sam,
            "attrs": build_user_attributes(user, attribute_names, object_classes),
            "enabled": user.enabled,
            "when_changed": user.when_changed,
        }


def do_migrate(
    cfg: dict[str, Any],
    bases: list[str],
    dry_run: bool,
    skip_ous: bool = False,
    skip_users: bool = False,
) -> None:
    ad_cfg, md_cfg, sync_cfg = cfg["source_ad"], cfg["target_md"], cfg["sync"]

    with ADSource(
        ad_cfg["server"], ad_cfg["bind_dn"], ad_cfg["password"], ad_cfg["base_dn"],
        use_ssl=ad_cfg.get("use_ssl", True), validate_cert=ad_cfg.get("validate_cert", True),
    ) as ad:
        md = MDClient(md_cfg["base_url"], verify_ssl=md_cfg.get("verify_ssl", True))
        md.login(md_cfg["username"], md_cfg["password"])
        try:
            state = load_state(sync_cfg["state_file"])
            if not skip_ous:
                migrate_ous(ad, md, bases, ad_cfg["base_dn"], md_cfg["base_dn"], dry_run)
            if not skip_users:
                migrate_users(ad, md, bases, ad_cfg["base_dn"], md_cfg["base_dn"], sync_cfg, state, dry_run)
            if not dry_run:
                save_state(sync_cfg["state_file"], state)
        finally:
            md.logout()


def cmd_migrate(args: argparse.Namespace, cfg: dict[str, Any]) -> None:
    bases = args.ou or cfg["organizational_units"] or [cfg["source_ad"]["base_dn"]]
    do_migrate(cfg, bases, args.dry_run, skip_ous=args.skip_ous, skip_users=args.skip_users)


# --------------------------------------------------------------------------- #
# sync: диф между текущим AD и сохранённым состоянием, применение изменений
# --------------------------------------------------------------------------- #
def sync_once(cfg: dict[str, Any], bases: list[str], dry_run: bool) -> None:
    ad_cfg, md_cfg, sync_cfg = cfg["source_ad"], cfg["target_md"], cfg["sync"]
    attribute_names = sync_cfg["attribute_names"]
    object_classes = sync_cfg["object_classes"]
    ad_base, md_base = ad_cfg["base_dn"], md_cfg["base_dn"]

    state = load_state(sync_cfg["state_file"])
    users_state: dict[str, Any] = state["users"]

    with ADSource(
        ad_cfg["server"], ad_cfg["bind_dn"], ad_cfg["password"], ad_cfg["base_dn"],
        use_ssl=ad_cfg.get("use_ssl", True), validate_cert=ad_cfg.get("validate_cert", True),
    ) as ad:
        md = MDClient(md_cfg["base_url"], verify_ssl=md_cfg.get("verify_ssl", True))
        md.login(md_cfg["username"], md_cfg["password"])
        try:
            # 1. Актуализируем структуру OU (новые OU в AD -> создаём в MD)
            migrate_ous(ad, md, bases, ad_base, md_base, dry_run)

            seen_guids: set[str] = set()

            # 2. Пользователи, которые сейчас есть в AD
            for user in ad.iter_users(bases):
                seen_guids.add(user.guid)
                target_dn = dn_utils.map_dn(user.dn, ad_base, md_base)
                new_attrs = build_user_attributes(user, attribute_names, object_classes)
                entry_state = users_state.get(user.guid)

                if entry_state is None:
                    # Новый пользователь в AD - создаём в MD
                    logger.info("[NEW] %s -> создаю в MD %s", user.dn, target_dn)
                    password = generate_password(sync_cfg["generated_password_length"])
                    if not dry_run:
                        md.add_entry(target_dn, new_attrs, password=password)
                        log_new_password(sync_cfg["password_log_file"], target_dn, user.sam, password)
                        if not user.enabled:
                            md.set_status(target_dn, locked=True)
                    users_state[user.guid] = {
                        "ad_dn": user.dn,
                        "md_dn": target_dn,
                        "sam": user.sam,
                        "attrs": new_attrs,
                        "enabled": user.enabled,
                        "when_changed": user.when_changed,
                    }
                    continue

                current_md_dn = entry_state["md_dn"]

                # 2a. Переименование и/или перемещение между OU
                if current_md_dn.lower() != target_dn.lower():
                    new_rdn = dn_utils.rdn(target_dn)
                    old_parent = dn_utils.parent_dn(current_md_dn)
                    new_parent = dn_utils.parent_dn(target_dn)
                    new_superior = new_parent if new_parent.lower() != old_parent.lower() else None
                    logger.info(
                        "[MOVE/RENAME] %s -> %s (newrdn=%s, new_superior=%s)",
                        current_md_dn, target_dn, new_rdn, new_superior,
                    )
                    if not dry_run:
                        md.rename_and_move(current_md_dn, new_rdn, new_superior, deleteoldrdn=True)
                    current_md_dn = target_dn
                    entry_state["md_dn"] = target_dn
                    entry_state["ad_dn"] = user.dn

                # 2b. Изменённые атрибуты
                old_attrs = entry_state.get("attrs", {})
                changes = []
                for key in set(new_attrs) | set(old_attrs):
                    if key == "objectClass":
                        continue
                    new_val = new_attrs.get(key)
                    old_val = old_attrs.get(key)
                    if new_val == old_val:
                        continue
                    changes.append((OP_REPLACE, key, new_val or []))
                if changes:
                    logger.info("[UPDATE] %s: изменённые атрибуты %s", current_md_dn, [c[1] for c in changes])
                    if not dry_run:
                        md.modify_entry(current_md_dn, changes)
                    entry_state["attrs"] = new_attrs

                # 2c. Включение/выключение
                if user.enabled != entry_state.get("enabled", True):
                    logger.info(
                        "[%s] %s", "ENABLE" if user.enabled else "DISABLE", current_md_dn
                    )
                    if not dry_run:
                        md.set_status(current_md_dn, locked=not user.enabled)
                    entry_state["enabled"] = user.enabled

                entry_state["when_changed"] = user.when_changed
                entry_state["sam"] = user.sam

            # 3. Пользователи, которые пропали из выбранных OU в AD
            on_missing = sync_cfg["on_missing_in_ad"]
            for guid, entry_state in list(users_state.items()):
                if guid in seen_guids:
                    continue
                ad_dn = entry_state.get("ad_dn", "")
                if not any(dn_utils.is_under(ad_dn, base) for base in bases):
                    # Эта учётка вне текущего набора отслеживаемых OU -
                    # не трогаем её в этом запуске.
                    continue

                md_dn = entry_state["md_dn"]
                if on_missing == "delete":
                    logger.info("[DELETE] пропал в AD: %s -> удаляю в MD %s", ad_dn, md_dn)
                    if not dry_run:
                        md.delete_entry(md_dn)
                        del users_state[guid]
                elif on_missing == "disable":
                    if entry_state.get("enabled", True):
                        logger.info("[DISABLE] пропал в AD: %s -> блокирую в MD %s", ad_dn, md_dn)
                        if not dry_run:
                            md.set_status(md_dn, locked=True)
                        entry_state["enabled"] = False
                else:
                    logger.debug("Пользователь %s пропал из AD, on_missing_in_ad=ignore", ad_dn)

            if not dry_run:
                save_state(sync_cfg["state_file"], state)
        finally:
            md.logout()


def cmd_sync(args: argparse.Namespace, cfg: dict[str, Any]) -> None:
    bases = args.ou or cfg["organizational_units"] or [cfg["source_ad"]["base_dn"]]

    if args.once or not args.interval:
        sync_once(cfg, bases, args.dry_run)
        return

    logger.info("Запуск в режиме демона, интервал %s секунд", args.interval)
    while True:
        try:
            sync_once(cfg, bases, args.dry_run)
        except MDError as exc:
            logger.error("Ошибка MultiDirectory: %s", exc)
        except Exception:
            logger.exception("Непредвиденная ошибка during sync_once")
        time.sleep(args.interval)


# --------------------------------------------------------------------------- #
# Мастер настройки: создаёт config.yaml по ответам в консоли, чтобы не нужно
# было гадать, какие поля и в каком формате заполнять руками.
# --------------------------------------------------------------------------- #
def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def _ask_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    value = input(f"{prompt} [{hint}]: ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes", "д", "да")


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def _ask_host(prompt: str, default_host: str) -> str:
    """Спрашивает голый адрес сервера (без ldap://, ldaps://, http:// и т.п.).

    Если пользователь всё же введёт схему (в том числе с опечаткой вроде
    "ladps://") -- она отбрасывается, чтобы опечатка в ней не привела к
    неверно собранному URL и путанице с отдельным вопросом про LDAPS/TLS.
    """
    value = _ask(prompt, default_host)
    stripped = _SCHEME_RE.sub("", value).strip().rstrip("/")
    if stripped != value:
        print(f"  (схема из адреса убрана, использую: {stripped!r})")
    return stripped or default_host


def _ask_base_dn(prompt: str, default: str) -> str:
    """Base DN -- это корень домена (только компоненты dc=...), а не DN
    конкретного пользователя или OU. Переспрашиваем, пока не введут именно его,
    чтобы не повторить ошибку вида "cn=admin,cn=Users,dc=...,dc=..." на месте
    base DN.
    """
    while True:
        value = _ask(prompt, default)
        try:
            comps = dn_utils.components(value)
        except Exception as exc:
            print(f"  Не удалось разобрать значение как DN: {exc}. Попробуйте ещё раз.")
            continue
        bad = [c for c in comps if not c.lower().startswith("dc=")]
        if bad or not comps:
            print(
                "  Base DN должен состоять только из компонентов dc=... (это корень "
                "домена), например 'DC=corp,DC=example,DC=local'.\n"
                f"  Вы ввели компонент(ы), которые не являются dc=: {', '.join(bad) or '(пусто)'}.\n"
                "  Похоже, это DN конкретного объекта (пользователя, OU и т.п.), а не "
                "базовый DN домена -- введите ещё раз."
            )
            continue
        return value


def run_config_wizard(path: str) -> dict[str, Any]:
    """Интерактивно спрашивает адреса/учётки AD и MD и сохраняет config.yaml."""
    print("=== Мастер настройки ad_md_sync ===")
    print(
        "Сейчас потребуется указать адрес контроллера домена AD и адрес REST API\n"
        "MultiDirectory, а также служебные учётные записи для чтения AD и записи в MD.\n"
    )

    print("--- Источник: Microsoft Active Directory ---")
    ad_host = _ask_host("Адрес контроллера домена (имя или IP, без ldap://)", "dc1.corp.example.local")
    ad_use_ssl = _ask_yes_no("Использовать LDAPS (шифрованное соединение, порт 636)?", True)
    ad_server = f"{'ldaps' if ad_use_ssl else 'ldap'}://{ad_host}"
    ad_validate_cert = True
    if ad_use_ssl:
        ad_validate_cert = _ask_yes_no("Проверять сертификат сервера AD?", True)
    print(
        "\n  Нужна отдельная служебная учётная запись для ЧТЕНИЯ AD (не ваша личная,\n"
        "  не Administrator). Как её безопасно завести -- см. README, раздел\n"
        "  «Служебные учётные записи». Для входа проще всего указать её UPN\n"
        "  (логин вида user@domain, тот же формат, что и при входе в Windows/почту) --\n"
        "  полный DN тоже подойдёт, но вводить и искать его вручную не нужно.\n"
    )
    ad_bind_dn = _ask(
        "Логин служебной учётной записи для чтения AD (UPN, например svc-md-sync@corp.example.local)",
        "svc-md-sync@corp.example.local",
    )
    ad_password = getpass.getpass("Пароль этой учётной записи AD (ввод скрыт): ")
    ad_base_dn = _ask_base_dn(
        "Base DN домена AD -- корень домена, только dc=... (НЕ DN пользователя/OU)",
        "DC=corp,DC=example,DC=local",
    )

    print("\n--- Приёмник: MultiDirectory ---")
    md_base_url = _ask("Базовый URL REST API MultiDirectory", "https://md.corp.example.local/api")
    md_verify_ssl = _ask_yes_no("Проверять TLS-сертификат сервера MD?", True)
    print(
        "\n  Аналогично нужна отдельная служебная учётная запись в MD с правами на\n"
        "  запись только в целевые OU (не администратор домена целиком) -- см. README.\n"
        "  Для входа подойдёт короткий логин (sAMAccountName), UPN или DN -- MD\n"
        "  принимает любой из этих форматов.\n"
    )
    md_username = _ask("Логин служебной учётной записи MD (например svc-ad-sync)", "svc-md-sync")
    md_password = getpass.getpass("Пароль этой учётной записи MD (ввод скрыт): ")
    md_base_dn = _ask_base_dn(
        "Base DN домена MD -- корень домена, только dc=... (НЕ DN пользователя/OU)",
        "DC=md,DC=example,DC=local",
    )

    print("\n--- Прочее ---")
    on_missing = _ask("Что делать с учёткой в MD, если пользователь пропал из AD "
                       "(disable/delete/ignore)", "disable")
    if on_missing not in ("disable", "delete", "ignore"):
        print(f"Не распознано {on_missing!r}, использую 'disable'.")
        on_missing = "disable"

    cfg: dict[str, Any] = {
        "source_ad": {
            "server": ad_server,
            "bind_dn": ad_bind_dn,
            "password": ad_password,
            "base_dn": ad_base_dn,
            "use_ssl": ad_use_ssl,
            "validate_cert": ad_validate_cert,
        },
        "target_md": {
            "base_url": md_base_url,
            "username": md_username,
            "password": md_password,
            "base_dn": md_base_dn,
            "verify_ssl": md_verify_ssl,
        },
        "organizational_units": [],
        "sync": {
            "state_file": "./state.json",
            "on_missing_in_ad": on_missing,
            "object_classes": DEFAULT_OBJECT_CLASSES,
            "attribute_names": DEFAULT_ATTRIBUTE_NAMES,
            "generated_password_length": 20,
            "password_log_file": "./new_passwords.csv",
        },
    }

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    print(
        f"\nКонфигурация сохранена в {path!r}. Файл содержит пароли в открытом виде -- "
        "права на файл ограничены (chmod 600), но по возможности вынесите пароли в "
        "переменные окружения AD_BIND_PASSWORD / MD_BIND_PASSWORD и уберите их из файла.\n"
    )
    return load_config(path)


def _print_config_summary(cfg: dict[str, Any]) -> None:
    ad_cfg, md_cfg, sync_cfg = cfg["source_ad"], cfg["target_md"], cfg["sync"]
    print("\n--- Текущая конфигурация (пароли скрыты) ---")
    print(f"AD сервер:      {ad_cfg['server']}  (LDAPS: {ad_cfg.get('use_ssl', True)})")
    print(f"AD bind DN:     {ad_cfg['bind_dn']}")
    print(f"AD base DN:     {ad_cfg['base_dn']}")
    print(f"MD base_url:    {md_cfg['base_url']}")
    print(f"MD пользователь:{md_cfg['username']}")
    print(f"MD base DN:     {md_cfg['base_dn']}")
    print(f"OU по умолчанию:{cfg.get('organizational_units') or '(весь домен)'}")
    print(f"on_missing_in_ad: {sync_cfg['on_missing_in_ad']}")
    print(f"state_file:     {sync_cfg['state_file']}")
    print()


# --------------------------------------------------------------------------- #
# Интерактивное меню -- выбор действия и OU без запоминания флагов CLI.
# --------------------------------------------------------------------------- #
def _manual_ou_entry() -> list[str]:
    print("Вводите DN организационных юнитов по одному, пустая строка -- закончить.")
    result: list[str] = []
    while True:
        dn = input("OU DN> ").strip()
        if not dn:
            break
        result.append(dn)
    return result


def select_ous_interactive(cfg: dict[str, Any]) -> list[str]:
    ad_cfg = cfg["source_ad"]
    print("\nПодключаюсь к AD, чтобы показать список доступных OU...")
    ous: list[str] = []
    try:
        with ADSource(
            ad_cfg["server"], ad_cfg["bind_dn"], ad_cfg["password"], ad_cfg["base_dn"],
            use_ssl=ad_cfg.get("use_ssl", True), validate_cert=ad_cfg.get("validate_cert", True),
        ) as ad:
            ous = sorted(ad.iter_ou_dns([ad_cfg["base_dn"]]), key=dn_utils.depth)
    except Exception as exc:
        print(f"Не удалось получить список OU из AD: {exc}")

    if not ous:
        print("Список OU получить не удалось (или в домене нет OU).")
        if _ask_yes_no("Ввести DN нужных OU вручную?", False):
            return _manual_ou_entry()
        return cfg.get("organizational_units") or [ad_cfg["base_dn"]]

    print("\nНайденные в AD организационные юниты:")
    for i, dn in enumerate(ous, 1):
        print(f"  {i:>3}. {dn}")
    print(
        "\nВведите номера нужных OU через запятую (например: 1,3,5)\n"
        "  'all'    -- взять весь домен, без фильтра по OU\n"
        "  'manual' -- ввести DN вручную\n"
        "  <пусто>  -- использовать organizational_units из config.yaml"
    )
    choice = input("> ").strip()

    if choice.lower() == "all":
        return [ad_cfg["base_dn"]]
    if choice.lower() == "manual":
        return _manual_ou_entry()
    if not choice:
        return cfg.get("organizational_units") or [ad_cfg["base_dn"]]

    try:
        idxs = [int(x.strip()) for x in choice.split(",") if x.strip()]
        selected = [ous[i - 1] for i in idxs]
        if not selected:
            raise ValueError
        return selected
    except (ValueError, IndexError):
        print("Не удалось разобрать ввод, использую organizational_units из config.yaml.")
        return cfg.get("organizational_units") or [ad_cfg["base_dn"]]


def interactive_menu(config_path: str) -> int:
    if not os.path.exists(config_path):
        print(f"Файл конфигурации {config_path!r} не найден.")
        if not _ask_yes_no("Запустить мастер настройки и создать его сейчас?", True):
            print(
                f"Без конфигурации работать нельзя. Скопируйте config.example.yaml в "
                f"{config_path!r} и заполните вручную, либо запустите скрипт заново."
            )
            return 1
        cfg = run_config_wizard(config_path)
    else:
        cfg = load_config(config_path)

    while True:
        print("\n================= ad_md_sync =================")
        print(f"Конфигурация: {config_path}")
        print(f"  AD: {cfg['source_ad']['server']}  (base: {cfg['source_ad']['base_dn']})")
        print(f"  MD: {cfg['target_md']['base_url']}  (base: {cfg['target_md']['base_dn']})")
        print("------------------------------------------------")
        print("  1. Перенести пользователей и структуру OU из AD в MD (migrate)")
        print("  2. Синхронизировать изменения AD -> MD, один проход (sync)")
        print("  3. Синхронизировать в режиме демона, по интервалу")
        print("  4. Настроить подключение заново (пересоздать config.yaml)")
        print("  5. Показать текущую конфигурацию")
        print("  0. Выход")
        choice = input("Выберите пункт меню: ").strip().lower()

        if choice in ("0", "q", "quit", "exit", ""):
            return 0
        if choice == "4":
            cfg = run_config_wizard(config_path)
            continue
        if choice == "5":
            _print_config_summary(cfg)
            continue
        if choice not in ("1", "2", "3"):
            print("Некорректный пункт меню, попробуйте снова.")
            continue

        bases = select_ous_interactive(cfg)
        if not bases:
            print("OU не выбраны, действие отменено.")
            continue
        dry_run = _ask_yes_no("Тестовый прогон без реальных изменений (dry-run)?", False)

        try:
            if choice == "1":
                do_migrate(cfg, bases, dry_run)
                print("Перенос завершён.")
            elif choice == "2":
                sync_once(cfg, bases, dry_run)
                print("Синхронизация выполнена.")
            elif choice == "3":
                interval_raw = _ask("Интервал между проходами, секунд", "300")
                try:
                    interval = max(1, int(interval_raw))
                except ValueError:
                    interval = 300
                print(f"Синхронизация каждые {interval} сек. Остановить -- Ctrl+C.")
                while True:
                    try:
                        sync_once(cfg, bases, dry_run)
                    except MDError as exc:
                        logger.error("Ошибка MultiDirectory: %s", exc)
                    time.sleep(interval)
        except KeyboardInterrupt:
            print("\nОстановлено пользователем.")
        except MDError as exc:
            print(f"Ошибка MultiDirectory: {exc}")
        except Exception:
            logger.exception("Ошибка при выполнении выбранного действия")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Перенос и синхронизация пользователей AD -> MultiDirectory")
    parser.add_argument(
        "--config", default="config.yaml",
        help="Путь к YAML-конфигу (по умолчанию ./config.yaml; см. config.example.yaml)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный лог (DEBUG)")

    sub = parser.add_subparsers(dest="command")

    p_migrate = sub.add_parser("migrate", help="Разовый перенос OU и пользователей из AD в MD")
    p_migrate.add_argument(
        "--ou", action="append", help="DN конкретной OU для переноса (можно указать несколько раз)"
    )
    p_migrate.add_argument("--skip-ous", action="store_true", help="Не создавать структуру OU")
    p_migrate.add_argument("--skip-users", action="store_true", help="Не создавать пользователей")
    p_migrate.add_argument("--dry-run", action="store_true", help="Только показать, что будет сделано")
    p_migrate.set_defaults(func=cmd_migrate)

    p_sync = sub.add_parser("sync", help="Синхронизировать изменения AD -> MD")
    p_sync.add_argument("--ou", action="append", help="DN конкретной OU для синхронизации")
    p_sync.add_argument("--dry-run", action="store_true", help="Только показать, что будет сделано")
    p_sync.add_argument("--once", action="store_true", help="Выполнить один проход и выйти (по умолчанию)")
    p_sync.add_argument(
        "--interval", type=int, default=0,
        help="Если задан, скрипт работает как демон и повторяет синхронизацию каждые N секунд "
             "(для продакшена предпочтительнее cron/systemd timer + --once)",
    )
    p_sync.set_defaults(func=cmd_sync)

    sub.add_parser(
        "menu",
        help="Интерактивное меню с подсказками (запускается по умолчанию, если команда не указана)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    # Без указанной команды (в т.ч. просто "python ad_md_sync.py") запускаем
    # интерактивное меню -- оно само спросит про config.yaml, если его нет.
    command = args.command or "menu"
    if command == "menu":
        return interactive_menu(args.config)

    cfg = load_config(args.config)

    try:
        args.func(args, cfg)
    except MDError as exc:
        logger.error("Ошибка MultiDirectory: %s", exc)
        return 1
    except Exception:
        logger.exception("Скрипт завершился с ошибкой")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
