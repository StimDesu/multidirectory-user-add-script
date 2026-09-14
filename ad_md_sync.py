#!/usr/bin/env python3
"""
ad_md_sync.py - перенос и синхронизация пользователей из Microsoft AD в MultiDirectory (MD).

Команды:
    migrate   Разовый перенос: создать структуру OU и пользователей в MD.
    sync      Сравнить текущее состояние AD с MD и применить изменения
              (создание, переименование/перемещение, изменение атрибутов,
              включение/выключение учёток). Хранит состояние между запусками
              в state-файле, поэтому подходит для регулярного запуска по cron
              / systemd timer.

Примеры:
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
import logging
import os
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


def cmd_migrate(args: argparse.Namespace, cfg: dict[str, Any]) -> None:
    ad_cfg, md_cfg, sync_cfg = cfg["source_ad"], cfg["target_md"], cfg["sync"]
    bases = args.ou or cfg["organizational_units"] or [ad_cfg["base_dn"]]

    with ADSource(
        ad_cfg["server"], ad_cfg["bind_dn"], ad_cfg["password"], ad_cfg["base_dn"],
        use_ssl=ad_cfg.get("use_ssl", True), validate_cert=ad_cfg.get("validate_cert", True),
    ) as ad:
        md = MDClient(md_cfg["base_url"], verify_ssl=md_cfg.get("verify_ssl", True))
        md.login(md_cfg["username"], md_cfg["password"])
        try:
            state = load_state(sync_cfg["state_file"])
            if not args.skip_ous:
                migrate_ous(ad, md, bases, ad_cfg["base_dn"], md_cfg["base_dn"], args.dry_run)
            if not args.skip_users:
                migrate_users(ad, md, bases, ad_cfg["base_dn"], md_cfg["base_dn"], sync_cfg, state, args.dry_run)
            if not args.dry_run:
                save_state(sync_cfg["state_file"], state)
        finally:
            md.logout()


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
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Перенос и синхронизация пользователей AD -> MultiDirectory")
    parser.add_argument("--config", required=True, help="Путь к YAML-конфигу (см. config.example.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный лог (DEBUG)")

    sub = parser.add_subparsers(dest="command", required=True)

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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

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
