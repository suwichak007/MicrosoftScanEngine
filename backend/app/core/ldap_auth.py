from dataclasses import dataclass

from fastapi import HTTPException, status

from app.core.config import (
    LDAP_ADMIN_GROUP_DN,
    LDAP_BIND_DN,
    LDAP_BIND_PASSWORD,
    LDAP_DEFAULT_ROLE,
    LDAP_DOMAIN,
    LDAP_SERVER_URI,
    LDAP_USER_BASE_DN,
    LDAP_USER_FILTER,
)


@dataclass
class LdapUser:
    username: str
    display_name: str
    email: str
    role: str


def _require_ldap3():
    try:
        from ldap3 import ALL, NTLM, Connection, Server
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="LDAP login is enabled but ldap3 is not installed. Run: pip install ldap3",
        ) from exc
    return ALL, NTLM, Connection, Server


def _escape_filter_value(value: str) -> str:
    return (
        value.replace("\\", r"\5c")
        .replace("*", r"\2a")
        .replace("(", r"\28")
        .replace(")", r"\29")
        .replace("\x00", r"\00")
    )


def _direct_bind_name(username: str) -> str:
    if "\\" in username or "@" in username or not LDAP_DOMAIN:
        return username
    return f"{LDAP_DOMAIN}\\{username}"


def _connect(bind_user: str, password: str):
    ALL, NTLM, Connection, Server = _require_ldap3()
    server = Server(LDAP_SERVER_URI, get_info=ALL)
    authentication = NTLM if "\\" in bind_user else None
    return Connection(
        server,
        user=bind_user,
        password=password,
        authentication=authentication,
        auto_bind=True,
    )


def authenticate_ldap(username: str, password: str) -> LdapUser:
    if not LDAP_SERVER_URI:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="LDAP_SERVER_URI is not configured",
        )
    if not password:
        raise HTTPException(status_code=400, detail="Username or password incorrect")

    escaped_username = _escape_filter_value(username)
    search_filter = LDAP_USER_FILTER.format(username=escaped_username)
    attributes = ["sAMAccountName", "userPrincipalName", "displayName", "mail", "memberOf"]

    try:
        if LDAP_BIND_DN and LDAP_BIND_PASSWORD and LDAP_USER_BASE_DN:
            lookup_conn = _connect(LDAP_BIND_DN, LDAP_BIND_PASSWORD)
            lookup_conn.search(LDAP_USER_BASE_DN, search_filter, attributes=attributes)
            if not lookup_conn.entries:
                lookup_conn.unbind()
                raise HTTPException(status_code=400, detail="Username or password incorrect")

            entry = lookup_conn.entries[0]
            user_dn = entry.entry_dn
            member_of = [str(group).lower() for group in getattr(entry, "memberOf", [])]

            user_conn = _connect(user_dn, password)
            user_conn.unbind()
            lookup_conn.unbind()
        else:
            bind_name = _direct_bind_name(username)
            user_conn = _connect(bind_name, password)
            user_dn = user_conn.user or bind_name
            member_of = []
            entry = None
            user_conn.unbind()

        role = LDAP_DEFAULT_ROLE if LDAP_DEFAULT_ROLE in ("admin", "viewer") else "viewer"
        if LDAP_ADMIN_GROUP_DN and LDAP_ADMIN_GROUP_DN.lower() in member_of:
            role = "admin"

        account_name = username
        display_name = username
        email = ""
        if entry is not None:
            sam = getattr(entry, "sAMAccountName", None)
            upn = getattr(entry, "userPrincipalName", None)
            display = getattr(entry, "displayName", None)
            mail = getattr(entry, "mail", None)
            account_name = str(sam or upn or username)
            display_name = str(display or account_name)
            email = str(mail or "")

        return LdapUser(
            username=account_name,
            display_name=display_name,
            email=email,
            role=role,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Username or password incorrect")
