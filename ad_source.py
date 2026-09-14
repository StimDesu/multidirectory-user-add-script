"""
Источник данных: Microsoft Active Directory через LDAP/LDAPS (ldap3).

Читает пользователей и организационные юниты из выбранных OU.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from ldap3 import ALL, SUBTREE, Connection, Server, Tls

logger = logging.getLogger(__name__)

# userAccountControl, бит ACCOUNTDISABLE
UAC_ACCOUNTDISABLE = 0x0002

USER_ATTRS = [
    "distinguishedName",
    "cn",
    "sAMAccountName",
    "userPrincipalName",
    "givenName",
    "sn",
    "displayName",
    "mail",
    "telephoneNumber",
    "userAccountControl",
    "whenChanged",
]

OU_FILTER = "(objectClass=organizationalUnit)"
# objectCategory=person отсекает сервисные/computer-объекты с objectClass=user
USER_FILTER_TEMPLATE = "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)){extra})"


@dataclass
class ADUser:
    dn: str
    guid: str
    sam: str | None
    upn: str | None
    cn: str
    given_name: str | None
    sn: str | None
    display_name: str | None
    mail: str | None
    phone: str | None
    enabled: bool
    when_changed: str | None
    raw: dict = field(default_factory=dict, repr=False)


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _guid_to_str(raw) -> str:
    if isinstance(raw, uuid.UUID):
        return str(raw)
    if isinstance(raw, (bytes, bytearray)):
        return str(uuid.UUID(bytes_le=bytes(raw)))
    return str(raw)


class ADSource:
    def __init__(
        self,
        server_uri: str,
        bind_dn: str,
        password: str,
        base_dn: str,
        use_ssl: bool = True,
        validate_cert: bool = True,
    ):
        self.base_dn = base_dn
        tls = None
        if use_ssl and not validate_cert:
            import ssl

            tls = Tls(validate=ssl.CERT_NONE)
        self.server = Server(server_uri, use_ssl=use_ssl, tls=tls, get_info=ALL)
        self.conn = Connection(self.server, user=bind_dn, password=password, auto_bind=True)
        logger.info("Подключение к AD %s выполнено (bind: %s)", server_uri, bind_dn)

    def close(self) -> None:
        self.conn.unbind()

    def __enter__(self) -> "ADSource":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _paged_search(self, base: str, filter_: str, attributes: list[str]) -> Iterator[dict]:
        entries = self.conn.extend.standard.paged_search(
            search_base=base,
            search_filter=filter_,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=500,
            generator=True,
        )
        for entry in entries:
            if entry.get("type") != "searchResEntry":
                continue
            yield entry

    def iter_ou_dns(self, bases: Iterable[str] | None = None) -> Iterator[str]:
        """DN всех organizationalUnit под указанными базами (без дублей)."""
        bases = list(bases) if bases else [self.base_dn]
        seen: set[str] = set()
        for base in bases:
            for entry in self._paged_search(base, OU_FILTER, ["distinguishedName"]):
                dn = entry["dn"]
                if dn in seen:
                    continue
                seen.add(dn)
                yield dn

    def iter_users(self, bases: Iterable[str] | None = None, extra_filter: str = "") -> Iterator[ADUser]:
        bases = list(bases) if bases else [self.base_dn]
        filter_ = USER_FILTER_TEMPLATE.format(extra=extra_filter)
        seen: set[str] = set()
        for base in bases:
            for entry in self._paged_search(base, filter_, USER_ATTRS):
                dn = entry["dn"]
                if dn in seen:
                    continue
                seen.add(dn)

                attrs = entry.get("attributes", {})
                raw_attrs = entry.get("raw_attributes", {})

                uac = int(_first(attrs.get("userAccountControl")) or 0)
                guid_raw = _first(raw_attrs.get("objectGUID"))
                guid = _guid_to_str(guid_raw) if guid_raw is not None else dn

                yield ADUser(
                    dn=dn,
                    guid=guid,
                    sam=_first(attrs.get("sAMAccountName")),
                    upn=_first(attrs.get("userPrincipalName")),
                    cn=_first(attrs.get("cn")) or "",
                    given_name=_first(attrs.get("givenName")),
                    sn=_first(attrs.get("sn")),
                    display_name=_first(attrs.get("displayName")),
                    mail=_first(attrs.get("mail")),
                    phone=_first(attrs.get("telephoneNumber")),
                    enabled=not bool(uac & UAC_ACCOUNTDISABLE),
                    when_changed=str(_first(attrs.get("whenChanged")) or ""),
                    raw=attrs,
                )
