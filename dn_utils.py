"""Работа с DN: разбор компонентов и перенос поддерева из одной базы в другую."""

from __future__ import annotations

from ldap3.utils.dn import parse_dn


def components(dn: str) -> list[str]:
    """Список компонентов DN вида ['CN=Ivan Petrov', 'OU=Moscow', 'DC=corp', ...]."""
    return [f"{attr}={val}" for attr, val, _ in parse_dn(dn)]


def rdn(dn: str) -> str:
    """Первый компонент DN (relative DN), например 'CN=Ivan Petrov'."""
    return components(dn)[0]


def parent_dn(dn: str) -> str:
    """DN родительского контейнера."""
    return ",".join(components(dn)[1:])


def depth(dn: str) -> int:
    return len(components(dn))


def is_under(dn: str, base_dn: str) -> bool:
    dn_parts = components(dn)
    base_parts = components(base_dn)
    if len(dn_parts) < len(base_parts):
        return False
    tail = dn_parts[len(dn_parts) - len(base_parts):]
    return [p.lower() for p in tail] == [p.lower() for p in base_parts]


def map_dn(dn: str, source_base: str, target_base: str) -> str:
    """Перекладывает DN из-под source_base в target_base, сохраняя цепочку OU/CN.

    Пример:
        map_dn("CN=Ivan,OU=Moscow,DC=corp,DC=local", "DC=corp,DC=local", "DC=md,DC=local")
        -> "CN=Ivan,OU=Moscow,DC=md,DC=local"
    """
    if not is_under(dn, source_base):
        raise ValueError(f"{dn!r} не находится внутри базового DN {source_base!r}")
    dn_parts = components(dn)
    base_parts = components(source_base)
    relative = dn_parts[: len(dn_parts) - len(base_parts)]
    return ",".join(relative + components(target_base))
