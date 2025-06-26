from collections import deque
import threading
import time
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from ldap3 import Server, Connection, ALL, NTLM
import pyodbc
import os
import json
import re
import logging
from logging.handlers import SysLogHandler

# Maximum number of rows returned from a SELECT query in the UI.
# Prevents memory issues with extremely large result sets.
MAX_ROWS = 10000
from web.paths import (
    ALLOWED_USERS_PATH,
    ADMIN_USERS_PATH,
    PERMISSIONS_PATH,
    SQL_SERVERS_PATH,
    QUERY_LOG_PATH,
)

def _detect_external_db(query, target_db):
    """Return referenced DB name if query points to another database."""
    use_match = re.search(r"\bUSE\s+(?:\[(?P<br>[^\]]+)\]|(?P<plain>\w+))", query, re.IGNORECASE)
    if use_match:
        db = use_match.group('br') or use_match.group('plain')
        if db.lower() != target_db.lower():
            return db

    patterns = [
        # three-part name: [DB].[schema].[table] or DB.schema.table (schema/table optional brackets)
        re.compile(
            r"(?:\[(?P<br>[^\]]+)\]|(?P<plain>\w+))\s*\.\s*(?:\[(?:[^\]]+)\]|\w+)\s*\.\s*(?:\[(?:[^\]]+)\]|\w+)",
            re.IGNORECASE,
        ),
        # two-part name using .. syntax: DB..table
        re.compile(
            r"(?:\[(?P<br>[^\]]+)\]|(?P<plain>\w+))\s*\.\.\s*(?:\[[^\]]+\]|\w+)",
            re.IGNORECASE,
        ),
    ]

    for pat in patterns:
        for m in pat.finditer(query):
            db = m.group('br') or m.group('plain')
            if db.lower() != target_db.lower():
                return db

    return None

# Detect UPDATE/DELETE after optional comments or SET/DECLARE statements
_DML_START_RE = re.compile(
    r"^(?:\s*(?:--[^\n]*\n|/\*.*?\*/\s*|(?:SET|DECLARE)\b[^;]*;))*\s*(DELETE|UPDATE)\b",
    re.IGNORECASE | re.DOTALL,
)


def _starts_with_update_or_delete(sql: str) -> bool:
    """Return True if sql begins with UPDATE or DELETE after stripping comments and SET/DECLARE."""
    return bool(_DML_START_RE.match(sql))

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key")

# LDAP ayarları
LDAP_SERVER = os.getenv("LDAP_SERVER", "ldap://10.0.0.201")
LDAP_DOMAIN = os.getenv("LDAP_DOMAIN", "BAYLAN")

# SQL bağlantı bilgileri
PROD_SQL = os.getenv("PROD_SQL_SERVER", "10.10.10.61")
DEV_SQL = os.getenv("DEV_SQL_SERVER", "172.35.10.29")
SQL_USER = os.getenv("SQL_USER", "devflask")
SQL_PASSWORD = os.getenv("SQL_PASSWORD", "StrongP@ss123")
BACKUP_SHARE_PATH = os.getenv("BACKUP_SHARE_PATH", r"\\172.35.10.29\Backups")
DEV_DATA_PATH = os.getenv("DEV_DATA_PATH", r"D:\SQLData")

# Wazuh syslog configuration
WAZUH_SYSLOG_HOST = os.getenv("WAZUH_SYSLOG_HOST", "127.0.0.1")
WAZUH_SYSLOG_PORT = int(os.getenv("WAZUH_SYSLOG_PORT", "514"))
WAZUH_SYSLOG_PREFIX = os.getenv("WAZUH_SYSLOG_PREFIX", "")
syslog_handler = SysLogHandler(address=(WAZUH_SYSLOG_HOST, WAZUH_SYSLOG_PORT))
if WAZUH_SYSLOG_PREFIX:
    syslog_handler.ident = f"{WAZUH_SYSLOG_PREFIX}: "
query_logger = logging.getLogger("query_logger")
query_logger.setLevel(logging.INFO)
if not query_logger.handlers:
    query_logger.addHandler(syslog_handler)

active_job = None
job_queue = deque()
active_jobs = {}

def is_admin():
    try:
        with open(ADMIN_USERS_PATH) as f:
            admins = [line.strip() for line in f]
        return session.get('user') in admins
    except:
        return False

def get_conn(server_ip):
    return pyodbc.connect(
        f"DRIVER={{ODBC Driver 18 for SQL Server}};"
        f"SERVER={server_ip};UID={SQL_USER};PWD={SQL_PASSWORD};TrustServerCertificate=yes",
        autocommit=True
    )

def load_sql_servers():
    try:
        with open(SQL_SERVERS_PATH) as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] SQL sunucu listesi yüklenemedi: {e}")
        return {}

def load_query_logs(limit=100):
    """Read last `limit` lines from query log file."""
    try:
        with open(QUERY_LOG_PATH, encoding="utf-8") as f:
            lines = deque(f, maxlen=limit)
        logs = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                logs.append({
                    "ts": entry.get("timestamp"),
                    "user": entry.get("user"),
                    "db": entry.get("database"),
                    "query": entry.get("query"),
                })
            except json.JSONDecodeError:
                parts = line.split(" | ", 3)
                if len(parts) == 4:
                    ts, user, db, query = parts
                    logs.append({"ts": ts, "user": user, "db": db, "query": query})
        return logs
    except Exception as e:
        print(f"[WARN] query log read failed: {e}")
        return []

def run_backup_restore(prod_db, dev_db, username, source_sql):
    try:
        active_jobs[dev_db] = {"stage": "backup", "percent": 0}

        # 🔹 STEP 1: BACKUP
        prod_conn = get_conn(source_sql)
        prod_cursor = prod_conn.cursor()
        bak_file = f"{BACKUP_SHARE_PATH}\\{prod_db}.bak"
        prod_cursor.execute(f"BACKUP DATABASE [{prod_db}] TO DISK = N'{bak_file}' WITH INIT")
        while prod_cursor.nextset(): pass
        prod_conn.close()

        # 🔹 STEP 2: Get logical file list
        active_jobs[dev_db] = {"stage": "analyze", "percent": 0}
        dev_conn = get_conn(DEV_SQL)
        dev_cursor = dev_conn.cursor()
        dev_cursor.execute(f"RESTORE FILELISTONLY FROM DISK = N'{bak_file}'")
        filelist = dev_cursor.fetchall()

        # 🔹 STEP 3: Generate MOVE list dynamically
        mdf_index = 0
        ldf_index = 0
        move_clauses = []

        for row in filelist:
            logical_name = row[0]
            file_type = row[2]  # 'D' for data, 'L' for log

            if file_type == 'D':
                mdf_path = f"{DEV_DATA_PATH}\\{dev_db}_{mdf_index}.mdf"
                mdf_index += 1
                move_clauses.append(f"MOVE N'{logical_name}' TO N'{mdf_path}'")
            elif file_type == 'L':
                ldf_path = f"{DEV_DATA_PATH}\\{dev_db}_log{ldf_index}.ldf"
                ldf_index += 1
                move_clauses.append(f"MOVE N'{logical_name}' TO N'{ldf_path}'")

        move_sql = ",\n     ".join(move_clauses)

        # 🔹 STEP 4: RESTORE
        active_jobs[dev_db] = {"stage": "restore", "percent": 0}
        dev_cursor.execute(f"""
            RESTORE DATABASE [{dev_db}]
            FROM DISK = N'{bak_file}'
            WITH {move_sql},
                 REPLACE
        """)
        while dev_cursor.nextset(): pass
        dev_conn.close()

        # 🔹 STEP 5: Kullanıcıya db_owner yetkisi ver
        try:
            domain_user = f"BAYLAN\\{username}"
            conn = get_conn(DEV_SQL)
            cursor = conn.cursor()
            cursor.execute(f"""
                USE [{dev_db}];
                IF NOT EXISTS (
                    SELECT 1 FROM sys.database_principals WHERE name = N'{domain_user}'
                )
                BEGIN
                    CREATE USER [{domain_user}] FOR LOGIN [{domain_user}];
                END;
                ALTER ROLE db_owner ADD MEMBER [{domain_user}];
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[WARN] db_owner atanamadı → {dev_db} → {domain_user} → {e}")

    except Exception as e:
        print(f"[ERROR] {dev_db} işlem hatası: {e}")
    finally:
        active_jobs.pop(dev_db, None)

def job_worker():
    global active_job
    while True:
        if active_job is None and job_queue:
            job = job_queue.popleft()
            active_job = job
            run_backup_restore(job['prod_db'], job['dev_db'], job['username'], job['source_sql'])
            active_job = None
        else:
            time.sleep(1)

threading.Thread(target=job_worker, daemon=True).start()

@app.route('/api/my-dev-dbs')
def api_my_dev_dbs():
    if 'user' not in session:
        return jsonify({"dev_dbs": []})

    username = session['user']
    dev_dbs = []

    try:
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sys.databases WHERE name LIKE ?", f"%_dev_{username}")
        dev_dbs = [row[0] for row in cursor.fetchall()]
        conn.close()
    except:
        pass

    return jsonify({"dev_dbs": dev_dbs})

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_dn = f"BAYLAN\\{username}"

        try:
            from ldap3 import Server, Connection, ALL, NTLM
            server = Server("ldap://10.0.0.201", get_info=ALL)
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM)
            if conn.bind():
                # Kullanıcı izinli mi kontrol et
                try:
                    with open(ALLOWED_USERS_PATH) as f:
                        allowed_users = [line.strip().lower() for line in f.readlines()]
                except Exception as e:
                    return f"Yetkili kullanıcı listesi okunamadı: {e}", 500

                if username.lower() not in allowed_users:
                    error = "Bu kullanıcıya izin verilmedi"
                    return render_template("login.html", error=error)

                session['user'] = username
                return redirect(url_for('dashboard'))
            else:
                error = "Giriş başarısız: Kullanıcı adı veya şifre hatalı"
        except Exception as e:
            error = f"LDAP bağlantı hatası: {str(e)}"

    return render_template("login.html", error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET'])
def admin_panel():
    if not is_admin():
        return "Erişiminiz yok", 403

    # allowed_users.txt'yi oku
    try:
        with open(ALLOWED_USERS_PATH) as f:
            allowed_users = [line.strip() for line in f.readlines()]
    except:
        allowed_users = []

    # user_permissions.json içeriğini oku
    try:
        with open(PERMISSIONS_PATH, "r") as f:
            permissions = json.load(f)
    except:
        permissions = {}

    # Tüm SQL sunucularından veritabanı isimlerini grupla
    prod_dbs_grouped = {}
    sql_servers = load_sql_servers()

    for server_name, ip in sql_servers.items():
        try:
            conn = get_conn(ip)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sys.databases WHERE database_id > 4")
            prod_dbs_grouped[server_name] = [row[0] for row in cursor.fetchall()]
            conn.close()
        except:
            prod_dbs_grouped[server_name] = []

    # Tüm dev veritabanlarını (isim + oluşturulma tarihi ile) al
    all_dev_dbs = []
    try:
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name, create_date
            FROM sys.databases
            WHERE name NOT IN ('master','tempdb','model','msdb')
        """)
        rows = cursor.fetchall()
        all_dev_dbs = [{"name": row.name, "created": row.create_date.strftime("%Y-%m-%d %H:%M")} for row in rows]
        conn.close()
    except:
        pass

    query_logs = load_query_logs()

    return render_template(
        "admin.html",
        username=session['user'],
        allowed_users=allowed_users,
        dev_dbs=all_dev_dbs,
        permissions=permissions,
        prod_dbs_grouped=prod_dbs_grouped,
        query_logs=query_logs
    )

@app.route('/admin/add-user', methods=['POST'])
def admin_add_user():
    if not is_admin():
        return "Erişiminiz yok", 403

    new_user = request.form.get("new_user", "").strip().lower()

    if new_user:
        try:
            # Aynı kullanıcı zaten varsa tekrar yazma
            with open(ALLOWED_USERS_PATH, "r") as f:
                existing = [line.strip().lower() for line in f.readlines()]
            if new_user not in existing:
                with open(ALLOWED_USERS_PATH, "a") as f:
                    f.write(f"{new_user}\n")
        except Exception as e:
            return f"Kullanıcı eklenemedi: {e}", 500

    return redirect(url_for("admin_panel"))

@app.route('/admin/delete-user', methods=['POST'])
def admin_delete_user():
    if not is_admin():
        return "Erişiminiz yok", 403

    user_to_delete = request.form.get("user_to_delete", "").strip().lower()
    if not user_to_delete:
        return redirect(url_for("admin_panel"))

    try:
        with open(ALLOWED_USERS_PATH, "r") as f:
            lines = [line.strip() for line in f.readlines()]
        lines = [u for u in lines if u.lower() != user_to_delete]

        with open(ALLOWED_USERS_PATH, "w") as f:
            for u in lines:
                f.write(f"{u}\n")
    except Exception as e:
        return f"Kullanıcı silinemedi: {e}", 500

    return redirect(url_for("admin_panel"))

@app.route('/admin/delete-db', methods=['POST'])
def admin_delete_db():
    if not is_admin():
        return "Erişiminiz yok", 403

    dev_db = request.form.get("dev_db")
    if not dev_db:
        return redirect(url_for("admin_panel"))

    try:
        # Aktif işlemlerden source_sql al
        source_sql = PROD_SQL
        if active_job and active_job['dev_db'] == dev_db:
            source_sql = active_job.get('source_sql', PROD_SQL)

        # 1. Restore işlemi varsa dev sunucuda KILL et
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT session_id FROM sys.dm_exec_requests
            WHERE command = 'RESTORE DATABASE' AND DB_NAME(database_id) = ?
        """, dev_db)
        row = cursor.fetchone()
        if row:
            cursor.execute(f"KILL {row.session_id}")
            active_jobs.pop(dev_db, None)
        conn.close()

        # 2. Backup işlemi varsa kaynak sunucuda KILL et
        parts = dev_db.split('_')
        prod_db = dev_db if len(parts) < 3 else "_".join(parts[1:-1])
        conn = get_conn(source_sql)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT session_id FROM sys.dm_exec_requests
            WHERE command = 'BACKUP DATABASE' AND DB_NAME(database_id) = ?
        """, prod_db)
        row = cursor.fetchone()
        if row:
            cursor.execute(f"KILL {row.session_id}")
        conn.close()

        # 3. Veritabanını zorla sil
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(1) FROM sys.databases WHERE name = ?", dev_db)
        exists = cursor.fetchone()[0]
        if exists:
            cursor.execute(f"""
                ALTER DATABASE [{dev_db}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
                DROP DATABASE [{dev_db}];
            """)
        conn.close()

    except Exception as e:
        return f"Veritabanı silinemedi: {e}", 500

    return redirect(url_for("admin_panel"))

@app.route('/admin/update-permissions', methods=['POST'])
def update_permissions():
    if not is_admin():
        return "Erişiminiz yok", 403

    permissions = load_permissions()
    user = request.form.get("user")

    if not user:
        return "Geçersiz kullanıcı", 400

    # Kullanıcıya ait yeni sunucu → veritabanı listesi oluştur
    new_user_perms = {}

    for key in request.form:
        if key.startswith(f"perm-{user}-"):
            _, _, full = key.split("-", 2)
            if "::" in full:
                server, db = full.split("::", 1)
                if server not in new_user_perms:
                    new_user_perms[server] = []
                new_user_perms[server].append(db)

    # permissions.json içine güncel olarak kaydet
    permissions[user] = new_user_perms
    save_permissions(permissions)

    return redirect(url_for("admin_panel"))

@app.route('/create', methods=['POST'])
def create_dev_db():
    if 'user' not in session:
        return redirect(url_for('login'))

    prefix = request.form.get('prefix')  # Örnek: "main"
    prod_db = request.form.get('prod_db')  # Örnek: "baylan_bms"
    username = session['user']
    dev_db = f"{prefix}_{prod_db}_{username}"

    # 🔍 DEBUG
    print(f"[DEBUG] Kullanıcı: {username}")
    print(f"[DEBUG] Gelen prefix: {prefix}")
    print(f"[DEBUG] Gelen prod_db: {prod_db}")
    print(f"[DEBUG] Oluşturulacak dev_db: {dev_db}")

    # SQL sunucu IP'lerini al
    servers = load_sql_servers()
    if prefix not in servers:
        print(f"[ERROR] Tanımsız prefix: {prefix}")
        return f"Tanımsız sunucu prefix: {prefix}", 400

    source_sql = servers[prefix]

    # Kullanıcı izin kontrolü (yeni yapı)
    permissions = load_permissions()
    allowed = permissions.get(username, {}).get(prefix, [])

    print(f"[DEBUG] Kullanıcının izinli olduğu DB'ler ({prefix}): {allowed}")

    if prod_db not in allowed:
        print(f"[ERROR] {username} kullanıcısının {prefix} üzerinde {prod_db} yetkisi yok!")
        return "Bu işlemi yapma yetkiniz yok.", 403

    # Aynı dev veritabanı zaten işleniyor mu kontrol et
    job = {"prod_db": prod_db, "dev_db": dev_db, "username": username, "source_sql": source_sql}
    in_queue = any(j["dev_db"] == dev_db for j in job_queue)
    is_active = active_job and active_job["dev_db"] == dev_db
    if not in_queue and not is_active:
        job_queue.append(job)

    return redirect(url_for('dashboard'))

def load_permissions():
    try:
        with open(PERMISSIONS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

def save_permissions(permissions):
    try:
        with open(PERMISSIONS_PATH, "w") as f:
            json.dump(permissions, f, indent=2)
    except Exception as e:
        print(f"[ERROR] save_permissions: {e}")

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']

    # Dev SQL'deki kullanıcıya ait veritabanlarını al
    dev_dbs = []
    try:
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sys.databases WHERE name LIKE ?", f"%_{username}")
        dev_dbs = [row[0] for row in cursor.fetchall()]
        conn.close()
    except:
        pass

    # RAM'deki aktif işleri de dahil et
    user_jobs = [db for db in active_jobs if db.endswith(f"_{username}")]
    for job in user_jobs:
        if job not in dev_dbs:
            dev_dbs.append(job)

    # SQL sunucularını yükle
    sql_servers = load_sql_servers()

    # Kullanıcının yetkili olduğu veritabanları (yeni format)
    permissions = load_permissions()
    user_perms = permissions.get(username, {})
    print(f"[DEBUG] user_perms: {user_perms}")

    prod_dbs = []

    for prefix, ip in sql_servers.items():
        print(f"[DEBUG] checking {prefix} on {ip}")
        try:
            conn = get_conn(ip)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT d.name,
                       CAST(SUM(mf.size) * 8 / 1024 AS INT) AS size_mb
                FROM sys.databases d
                JOIN sys.master_files mf ON d.database_id = mf.database_id
                WHERE d.database_id > 4
                GROUP BY d.name
            """)
            rows = cursor.fetchall()
            for row in rows:
                print(f"[DEBUG] {prefix} - {row.name}")
                if row.name in user_perms.get(prefix, []):
                    prod_dbs.append({
                        "prefix": prefix,
                        "name": row.name,
                        "size_mb": row.size_mb
                    })
            conn.close()
        except Exception as e:
            print(f"[ERROR] {prefix} SQL sunucusundan veritabanları alınamadı → {e}")

    return render_template(
        "dashboard.html",
        username=username,
        prod_dbs=prod_dbs,
        dev_dbs=dev_dbs,
        active_job=active_job,
        job_queue=list(job_queue),
        is_admin=is_admin()
    )

@app.route('/delete', methods=['POST'])
def delete_dev_db():
    if 'user' not in session:
        return redirect(url_for('login'))

    dev_db = request.form['dev_db']
    username = session['user']

    # Dev DB kullanıcı kontrolü (yeni format: prod_dbname_i.hancioglu)
    if not dev_db.endswith(f"_{username}"):
        return "Bu işlemi yapamazsınız.", 403

    try:
        # Aktif işlemlerden source_sql bilgisi alınması gerekir
        source_sql = PROD_SQL  # default olarak PROD
        if active_job and active_job['dev_db'] == dev_db:
            source_sql = active_job.get('source_sql', PROD_SQL)

        # 1. Eğer bu veritabanı restore işlemindeyse
        if active_job and active_job['dev_db'] == dev_db:
            conn = get_conn(DEV_SQL)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT session_id FROM sys.dm_exec_requests
                WHERE command = 'RESTORE DATABASE' AND DB_NAME(database_id) = ?
            """, dev_db)
            row = cursor.fetchone()
            if row:
                cursor.execute(f"KILL {row.session_id}")
                conn.close()
                active_jobs.pop(dev_db, None)
                return redirect(url_for('dashboard'))

        # 2. Eğer bu veritabanı backup işlemindeyse
        if active_job and active_job.get('prod_db') and active_job['dev_db'] == dev_db:
            prod_db = active_job['prod_db']
            conn = get_conn(source_sql)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT session_id FROM sys.dm_exec_requests
                WHERE command = 'BACKUP DATABASE' AND DB_NAME(database_id) = ?
            """, prod_db)
            row = cursor.fetchone()
            if row:
                cursor.execute(f"KILL {row.session_id}")
                conn.close()
                active_jobs.pop(dev_db, None)
                return redirect(url_for('dashboard'))

        # 3. Bağlantıları kopararak zorla DROP
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(1) FROM sys.databases WHERE name = ?", dev_db)
        exists = cursor.fetchone()[0]
        if exists:
            cursor.execute(f"""
                ALTER DATABASE [{dev_db}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
                DROP DATABASE [{dev_db}];
            """)
        conn.close()
        return redirect(url_for('dashboard'))

    except Exception as e:
        return f"Hata: {str(e)}", 500

@app.route('/progress')
def progress():
    dev_db = request.args.get('dev_db')

    if not dev_db:
        return jsonify({
            "dev_db": "unknown",
            "stage": "error",
            "percent_complete": 0,
            "status": "invalid_request"
        })

    # prod_db adı: mesela mesafetest_BMS_i.hancioglu → BMS
    parts = dev_db.split("_")
    if len(parts) < 3:
        prod_db = dev_db
    else:
        prod_db = "_".join(parts[1:-1])

    # Kaynağın hangi SQL sunucusu olduğunu bul
    source_sql = active_jobs.get(dev_db, {}).get("source_sql", PROD_SQL)

    # 1. Prod sunucuda backup kontrolü (sql_text eşleşmesi zorunlu)
    try:
        conn = get_conn(source_sql)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.percent_complete, r.command, st.text AS sql_text
            FROM sys.dm_exec_requests r
            CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) AS st
            WHERE r.command = 'BACKUP DATABASE'
        """)
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            sql_text = row.sql_text or ''
            # BMS, [BMS], "BMS", N'BMS' gibi farklı formatlar olabilir
            normalized = sql_text.replace("[", "").replace("]", "").replace('"', "").replace("'", "").upper()
            if f"BACKUP DATABASE {prod_db.upper()}" in normalized:
                return jsonify({
                    "dev_db": dev_db,
                    "stage": "backup",
                    "percent_complete": int(row.percent_complete),
                    "status": "running"
                })
    except Exception as e:
        print(f"[BACKUP CHECK ERROR] {e}")

    # 2. Dev sunucuda restore kontrolü
    try:
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.percent_complete, r.command, st.text AS sql_text
            FROM sys.dm_exec_requests r
            CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) AS st
            WHERE r.command = 'RESTORE DATABASE'
        """)
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            if dev_db.lower() in (row.sql_text or '').lower():
                return jsonify({
                    "dev_db": dev_db,
                    "stage": "restore",
                    "percent_complete": int(row.percent_complete),
                    "status": "running"
                })
    except Exception as e:
        print(f"[RESTORE CHECK ERROR] {e}")

    # İşlem görünmüyorsa tamamlandı kabul et
    return jsonify({
        "dev_db": dev_db,
        "stage": "completed",
        "percent_complete": 100,
        "status": "done"
    })

@app.route('/cancel-queued', methods=['POST'])
def cancel_queued():
    if 'user' not in session:
        return redirect(url_for('dashboard'))

    dev_db = request.form['dev_db']
    username = session['user']
    for job in list(job_queue):
        if job['dev_db'] == dev_db and job['username'] == username:
            job_queue.remove(job)
            break
    return redirect(url_for('dashboard'))


def log_query(username, database, query_text):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')

    safe_query = re.sub(r'[\r\n]+', ' ', query_text).strip()
    record = {
        "timestamp": ts,
        "user": username,
        "database": database,
        "query": safe_query,
    }
    line = json.dumps(record, ensure_ascii=False)
    try:
        with open(QUERY_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[WARN] query log failed: {e}")

    try:
        query_logger.info(line)
    except Exception as e:
        print(f"[WARN] syslog failed: {e}")


@app.route('/query', methods=['GET', 'POST'])
def query_page():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    permissions = load_permissions()
    sql_servers = load_sql_servers()

    prod_dbs = []  # list of dicts with prefix and db
    for prefix, dbs in permissions.get(username, {}).items():
        for db in dbs:
            prod_dbs.append({'prefix': prefix, 'db': db})

    result = None
    columns = []
    error = None
    message = None
    selected_db = ""
    show_confirm = False
    pending_query = None
    affected_rows = None

    if request.method == 'GET':
        session.pop('pending_query', None)
        session.pop('pending_db', None)
        session.pop('affected', None)

    if request.method == 'POST':
        selected_db = request.form.get('database')
        selected = selected_db  # format: prefix::db
        query_text = request.form.get('query', '').strip()

        if not selected or '::' not in selected:
            error = "Veritabanı seçimi hatalı."
        else:
            prefix, database = selected.split('::', 1)
            allowed = any(item['prefix'] == prefix and item['db'] == database for item in prod_dbs)
            if not allowed:
                error = "Bu veritabanı için izniniz yok."
            elif not query_text:
                error = "Sorgu gereklidir."
            else:
                ip = sql_servers.get(prefix)
                if not ip:
                    error = "Sunucu bulunamadı."
                else:
                    other_db = _detect_external_db(query_text, database)
                    if other_db:
                        error = (
                            f"Sorgu içerisinde farklı bir veritabanı ('{other_db}') referansı tespit edildi."
                        )
                    else:
                        try:
                            conn = get_conn(ip)
                            cursor = conn.cursor()
                            cursor.execute(f"USE [{database}]")
                            if _starts_with_update_or_delete(query_text):
                                cursor.execute("BEGIN TRANSACTION")
                                cursor.execute(query_text)
                                cursor.execute("SELECT @@ROWCOUNT AS affected")
                                affected_rows = cursor.fetchone()[0]
                                cursor.execute("ROLLBACK")
                                conn.close()
                                session['pending_query'] = query_text
                                session['pending_db'] = selected
                                session['affected'] = affected_rows
                                pending_query = query_text
                                show_confirm = True
                            else:
                                cursor.execute(query_text)
                                if cursor.description is None:
                                    result = []
                                    columns = []
                                    message = "Query executed successfully."
                                else:
                                    rows = cursor.fetchmany(MAX_ROWS + 1)
                                    truncated = len(rows) > MAX_ROWS
                                    rows = rows[:MAX_ROWS]
                                    columns = [col[0] for col in cursor.description]
                                    result = [list(row) for row in rows]
                                    if truncated:
                                        message = f"Showing first {MAX_ROWS} rows."
                                log_query(username, f"{prefix}/{database}", query_text)
                        except Exception as e:
                            error = f"Sorgu hatası: {e}"
                        finally:
                            try:
                                conn.close()
                            except Exception:
                                pass

    return render_template(
        'query.html',
        username=username,
        prod_dbs=prod_dbs,
        result=result,
        columns=columns,
        error=error,
        message=message,
        selected_db=selected_db,
        show_confirm=show_confirm,
        pending_query=pending_query,
        affected=affected_rows,
    )


@app.route('/execute-query', methods=['POST'])
def execute_query():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    query_text = session.pop('pending_query', None)
    selected = session.pop('pending_db', None)
    session.pop('affected', None)

    if not query_text or not selected:
        return redirect(url_for('query_page'))

    permissions = load_permissions()
    sql_servers = load_sql_servers()

    prod_dbs = []
    for prefix, dbs in permissions.get(username, {}).items():
        for db in dbs:
            prod_dbs.append({'prefix': prefix, 'db': db})

    prefix, database = selected.split('::', 1)
    allowed = any(item['prefix'] == prefix and item['db'] == database for item in prod_dbs)

    result = None
    columns = []
    error = None
    message = None

    if not allowed:
        error = "Bu veritabanı için izniniz yok."
    else:
        ip = sql_servers.get(prefix)
        if not ip:
            error = "Sunucu bulunamadı."
        else:
            other_db = _detect_external_db(query_text, database)
            if other_db:
                error = (
                    f"Sorgu içerisinde farklı bir veritabanı ('{other_db}') referansı tespit edildi."
                )
            else:
                try:
                    conn = get_conn(ip)
                    cursor = conn.cursor()
                    cursor.execute(f"USE [{database}]")
                    cursor.execute(query_text)
                    cursor.execute("SELECT @@ROWCOUNT AS affected")
                    affected = cursor.fetchone()[0]
                    result = []
                    columns = []
                    message = f"Query executed successfully. {affected} rows affected."
                    log_query(username, f"{prefix}/{database}", query_text)
                except Exception as e:
                    error = f"Sorgu hatası: {e}"
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass

    return render_template(
        'query.html',
        username=username,
        prod_dbs=prod_dbs,
        result=result,
        columns=columns,
        error=error,
        message=message,
        selected_db=selected,
        show_confirm=False,
        pending_query=None,
        affected=None,
    )
