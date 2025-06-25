# web/paths.py
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")

ALLOWED_USERS_PATH = os.path.join(CONFIG_DIR, "allowed_users.txt")
ADMIN_USERS_PATH = os.path.join(CONFIG_DIR, "admin_users.txt")
PERMISSIONS_PATH = os.path.join(CONFIG_DIR, "user_permissions.json")
SQL_SERVERS_PATH = os.path.join(CONFIG_DIR, "sql_servers.json")
QUERY_LOG_PATH = os.path.join(CONFIG_DIR, "query_log.txt")
