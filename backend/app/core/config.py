import os

SECRET_KEY = os.environ.get("SECRET_KEY", "YOUR_SUPER_SECRET_KEY_HERE")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Authentication provider:
#   local  = use users table password hashes
#   ldap   = use LDAP only
#   hybrid = try LDAP first, then local users table
AUTH_PROVIDER = os.environ.get("AUTH_PROVIDER", "local").lower()

# LDAP / Active Directory settings
LDAP_SERVER_URI = os.environ.get("LDAP_SERVER_URI", "")
LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "")
LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")
LDAP_USER_BASE_DN = os.environ.get("LDAP_USER_BASE_DN", "")
LDAP_USER_FILTER = os.environ.get("LDAP_USER_FILTER", "(sAMAccountName={username})")
LDAP_DOMAIN = os.environ.get("LDAP_DOMAIN", "")
LDAP_DEFAULT_ROLE = os.environ.get("LDAP_DEFAULT_ROLE", "viewer")
LDAP_ADMIN_GROUP_DN = os.environ.get("LDAP_ADMIN_GROUP_DN", "")

# Development-only LDAP mock. Use this when AD/Azure AD DS details are not ready yet.
# Format: username:password:role:display_name:email,username2:password2:role
LDAP_MOCK_ENABLED = os.environ.get("LDAP_MOCK_ENABLED", "false").lower() in ("1", "true", "yes", "on")
LDAP_MOCK_USERS = os.environ.get("LDAP_MOCK_USERS", "")
