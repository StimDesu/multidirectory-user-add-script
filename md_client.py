"""
Клиент REST API MultiDirectory (MD).

Построен по openapi.json (MultiDirectory v3.2.0), лежащему в корне репозитория.
Аутентификация сессионная: POST /auth/ отдаёт куки, которые затем
автоматически используются requests.Session для всех остальных вызовов.

MultiDirectory реализует LDAP-подобный протокол поверх REST, поэтому
многие структуры (SearchRequest, ModifyRequest, ModifyDNRequest, LDAPResult
и коды результатов) - это прямое отражение RFC 4511.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

import requests

logger = logging.getLogger(__name__)

# -- LDAP-константы, используемые REST API MultiDirectory -------------------
SCOPE_BASE = 0
SCOPE_ONELEVEL = 1
SCOPE_SUBTREE = 2

DEREF_NEVER = 0

OP_ADD = 0
OP_DELETE = 1
OP_REPLACE = 2

LDAP_SUCCESS = 0
LDAP_NO_SUCH_OBJECT = 32
LDAP_ENTRY_ALREADY_EXISTS = 68

# /entry/status: судя по схеме (LockoutStatus: 0/1, directory_dn) это ближайший
# документированный способ заблокировать/разблокировать учётку через REST API.
# Если в вашей версии MD семантика иная (например, это именно lock, а не
# disable) -- замените вызовы set_status() на прямое изменение атрибута
# userAccountControl через modify_entry(), если MD его поддерживает.
STATUS_UNLOCKED = 0
STATUS_LOCKED = 1


class MDError(RuntimeError):
    """Ошибка обращения к MultiDirectory API."""


class MDClient:
    def __init__(self, base_url: str, verify_ssl: bool = True, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.timeout = timeout

    # -- аутентификация -------------------------------------------------
    def login(self, username: str, password: str) -> None:
        resp = self.session.post(
            f"{self.base_url}/auth/",
            data={"username": username, "password": password},
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise MDError(
                f"Не удалось выполнить вход в MultiDirectory ({resp.status_code}): {resp.text}"
            )
        payload = resp.json() if resp.content else None
        if payload:
            # Непустой ответ 200 -- это MFAChallengeResponse, т.е. сервер
            # запросил второй фактор. Скрипт для сервисной учётки такой
            # сценарий не обрабатывает -- отключите MFA для неё в MD либо
            # доработайте этот метод под ваш MFA-провайдер.
            raise MDError(
                "MultiDirectory запросил многофакторную аутентификацию для "
                f"сервисной учётной записи: {payload}. Отключите MFA для "
                "учётки синхронизации."
            )
        logger.info("Выполнен вход в MultiDirectory как %s", username)

    def logout(self) -> None:
        try:
            self.session.delete(f"{self.base_url}/auth/", timeout=self.timeout)
        except requests.RequestException:
            logger.warning("Не удалось корректно закрыть сессию MultiDirectory", exc_info=True)

    # -- низкоуровневый helper -------------------------------------------
    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        resp = self.session.request(method, f"{self.base_url}{path}", timeout=self.timeout, **kwargs)
        if resp.status_code in (401, 403):
            raise MDError(f"{method} {path}: доступ запрещён ({resp.status_code}): {resp.text}")
        if resp.status_code == 422:
            raise MDError(f"{method} {path}: ошибка валидации запроса: {resp.text}")
        if resp.status_code >= 400:
            raise MDError(f"{method} {path}: HTTP {resp.status_code}: {resp.text}")
        return resp

    # -- entry API ---------------------------------------------------------
    def search(
        self,
        base_object: str,
        filter_: str,
        attributes: list[str] | None = None,
        scope: int = SCOPE_SUBTREE,
        size_limit: int = 0,
    ) -> dict[str, Any]:
        body = {
            "base_object": base_object,
            "scope": scope,
            "deref_aliases": DEREF_NEVER,
            "size_limit": size_limit,
            "time_limit": 0,
            "types_only": False,
            "filter": filter_,
            "attributes": attributes or [],
        }
        resp = self._request("POST", "/entry/search", json=body)
        return resp.json()

    def entry_exists(self, dn: str) -> bool:
        result = self.search(dn, "(objectClass=*)", attributes=[], scope=SCOPE_BASE)
        if result.get("resultCode") == LDAP_NO_SUCH_OBJECT:
            return False
        return result.get("resultCode") == LDAP_SUCCESS and bool(result.get("search_result"))

    def add_entry(
        self,
        dn: str,
        attributes: dict[str, Iterable[str]],
        password: str | None = None,
        is_system: bool = False,
    ) -> dict[str, Any]:
        body = {
            "entry": dn,
            "is_system": is_system,
            "attributes": [{"type": k, "vals": list(v)} for k, v in attributes.items()],
            "password": password,
        }
        resp = self._request("POST", "/entry/add", json=body)
        result = resp.json()
        code = result.get("resultCode")
        if code not in (LDAP_SUCCESS, LDAP_ENTRY_ALREADY_EXISTS):
            raise MDError(f"Не удалось создать запись {dn}: {result}")
        return result

    def modify_entry(self, dn: str, changes: list[tuple[int, str, list[str]]]) -> dict[str, Any]:
        if not changes:
            return {"resultCode": LDAP_SUCCESS}
        body = {
            "object": dn,
            "changes": [
                {"operation": op, "modification": {"type": attr, "vals": vals}}
                for op, attr, vals in changes
            ],
        }
        resp = self._request("PATCH", "/entry/update", json=body)
        result = resp.json()
        if result.get("resultCode") != LDAP_SUCCESS:
            raise MDError(f"Не удалось изменить {dn}: {result}")
        return result

    def rename_and_move(
        self,
        dn: str,
        newrdn: str,
        new_superior: str | None,
        deleteoldrdn: bool = True,
    ) -> list[dict[str, Any]]:
        """Переименовать и/или переместить запись (ModifyDN).

        new_superior=None -- переименование без смены родительской OU.
        """
        body = [
            {
                "entry": dn,
                "newrdn": newrdn,
                "deleteoldrdn": deleteoldrdn,
                "new_superior": new_superior,
            }
        ]
        resp = self._request("POST", "/entry/update_many/dn", json=body)
        results = resp.json()
        for result in results:
            if result.get("resultCode") != LDAP_SUCCESS:
                raise MDError(f"Не удалось переименовать/переместить {dn}: {result}")
        return results

    def set_status(self, dn: str, locked: bool) -> None:
        body = {"directory_dn": dn, "status": STATUS_LOCKED if locked else STATUS_UNLOCKED}
        self._request("PUT", "/entry/status", json=body)

    def delete_entry(self, dn: str) -> dict[str, Any]:
        resp = self._request("DELETE", "/entry/delete", json={"entry": dn})
        result = resp.json()
        if result.get("resultCode") not in (LDAP_SUCCESS, LDAP_NO_SUCH_OBJECT):
            raise MDError(f"Не удалось удалить {dn}: {result}")
        return result
