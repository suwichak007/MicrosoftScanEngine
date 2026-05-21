from dataclasses import dataclass

from fastapi import HTTPException, status

from app.core.config import (
    LDAP_ADMIN_GROUP_DN,
    LDAP_BIND_DN,
    LDAP_BIND_PASSWORD,
    LDAP_DEFAULT_ROLE,
    LDAP_DOMAIN,
    LDAP_MOCK_ENABLED,
    LDAP_MOCK_USERS,
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


DEFAULT_MOCK_USERS = (
    "azure.admin@example.com:Test@12345:admin:Azure Admin:azure.admin@example.com,"
    "azure.viewer@example.com:Test@12345:viewer:Azure Viewer:azure.viewer@example.com"
)


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


def _mock_login(username: str, password: str) -> LdapUser | None:
    mock_users = LDAP_MOCK_USERS or DEFAULT_MOCK_USERS
    normalized_username = username.strip().lower()

    for raw_user in mock_users.split(","):
        parts = [part.strip() for part in raw_user.split(":")]
        if len(parts) < 3:
            continue

        mock_username, mock_password, mock_role = parts[:3]
        mock_display_name = parts[3] if len(parts) > 3 and parts[3] else mock_username
        mock_email = parts[4] if len(parts) > 4 and parts[4] else (
            mock_username if "@" in mock_username else ""
        )

        aliases = {mock_username.lower()}
        if "@" in mock_username:
            aliases.add(mock_username.split("@", 1)[0].lower())

        if normalized_username in aliases and password == mock_password:
            role = mock_role if mock_role in ("admin", "viewer") else "viewer"
            return LdapUser(
                username=mock_username,
                display_name=mock_display_name,
                email=mock_email,
                role=role,
            )

    return None


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
    if LDAP_MOCK_ENABLED:
        mock_user = _mock_login(username, password)
        if mock_user:
            return mock_user
        raise HTTPException(status_code=400, detail="Username or password incorrect")

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
