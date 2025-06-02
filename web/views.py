from collections import deque
import threading
import time
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from ldap3 import Server, Connection, ALL, NTLM
import pyodbc
import os
import json
from web.paths import ALLOWED_USERS_PATH, ADMIN_USERS_PATH, PERMISSIONS_PATH

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# LDAP ayarları
LDAP_SERVER = 'ldap://10.0.0.201'
LDAP_DOMAIN = 'BAYLAN'

# SQL bağlantı bilgileri
PROD_SQL = "10.10.10.61"
DEV_SQL = "172.35.10.29"
SQL_USER = "devflask"
SQL_PASSWORD = "StrongP@ss123"
BACKUP_SHARE_PATH = r"\\172.35.10.29\Backups"
DEV_DATA_PATH = r"D:\SQLData"

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

def run_backup_restore(prod_db, dev_db, username):
    try:
        active_jobs[dev_db] = {"stage": "backup", "percent": 0}

        # 🔹 STEP 1: BACKUP
        prod_conn = get_conn(PROD_SQL)
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
            run_backup_restore(job['prod_db'], job['dev_db'], job['username'])
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

    # Prod veritabanı adlarını al
    prod_dbs = []
    try:
        conn = get_conn(PROD_SQL)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sys.databases WHERE database_id > 4")
        prod_dbs = [row[0] for row in cursor.fetchall()]
        conn.close()
    except:
        pass

    # Tüm dev veritabanlarını (isim + oluşturulma tarihi ile) al
    all_dev_dbs = []
    try:
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name, create_date
            FROM sys.databases
            WHERE name LIKE '%_dev_%'
        """)
        rows = cursor.fetchall()
        all_dev_dbs = [{"name": row.name, "created": row.create_date.strftime("%Y-%m-%d %H:%M")} for row in rows]
        conn.close()
    except:
        pass

    return render_template(
        "admin.html",
        username=session['user'],
        allowed_users=allowed_users,
        dev_dbs=all_dev_dbs,
        permissions=permissions,
        prod_dbs=prod_dbs  # ✅ Checkbox için gerekli
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

    try:
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

    # 🟡 Eski izinleri oku
    try:
        with open(PERMISSIONS_PATH) as f:
            all_permissions = json.load(f)
    except:
        all_permissions = {}

    # 🔄 Formdan gelen güncellemeleri al
    updated = {}
    for key in request.form:
        if key.startswith("perm-"):
            _, user, db = key.split("-", 2)
            updated.setdefault(user, []).append(db)

    # 🧩 Güncel bilgileri eski kayıtlarla birleştir
    for user, dbs in updated.items():
        all_permissions[user] = dbs  # sadece ilgili kullanıcı güncellenir, diğerleri korunur

    # 💾 Kaydet
    try:
        with open(PERMISSIONS_PATH, "w") as f:
            json.dump(all_permissions, f, indent=4)
    except Exception as e:
        return f"İzinler kaydedilemedi: {e}", 500

    return redirect(url_for("admin_panel"))

@app.route('/create', methods=['POST'])
def create_dev_db():
    if 'user' not in session:
        return redirect(url_for('login'))

    prod_db = request.form['prod_db']
    username = session['user']
    dev_db = f"{prod_db}_dev_{username}"

    # Kullanıcı izin kontrolü
    permissions = load_permissions()
    allowed_dbs = permissions.get(username, [])
    if prod_db not in allowed_dbs:
        return "Bu işlemi yapma yetkiniz yok.", 403

    # Zaten aktif ya da kuyruktaysa tekrar ekleme
    job = {"prod_db": prod_db, "dev_db": dev_db, "username": username}
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

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']

    # Dev veritabanları
    dev_dbs = []
    try:
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sys.databases WHERE name LIKE ?", f"%_dev_{username}")
        dev_dbs = [row[0] for row in cursor.fetchall()]
        conn.close()
    except:
        pass

    # RAM'deki aktif işleri de dahil et
    user_jobs = [db for db in active_jobs if db.endswith(f"_dev_{username}")]
    for job in user_jobs:
        if job not in dev_dbs:
            dev_dbs.append(job)

    # Tüm prod veritabanları
    prod_dbs_all = []
    try:
        conn = get_conn(PROD_SQL)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT d.name,
                   CAST(SUM(mf.size) * 8 / 1024 AS INT) AS size_mb
            FROM sys.databases d
            JOIN sys.master_files mf ON d.database_id = mf.database_id
            WHERE d.database_id > 4
            GROUP BY d.name
        """)
        prod_dbs_all = [{"name": row.name, "size_mb": row.size_mb} for row in cursor.fetchall()]
        conn.close()
    except:
        pass

    # Kullanıcının yetkili olduğu prod veritabanları
    permissions = load_permissions()
    allowed = permissions.get(username, [])
    prod_dbs = [db for db in prod_dbs_all if db["name"] in allowed]

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

    # Kendi veritabanı mı?
    if not dev_db.endswith(f"_dev_{username}"):
        return "Bu işlemi yapamazsınız.", 403

    try:
        # 1. Eğer bu veritabanı aktif işlemdeyse (restore)
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

        # 2. Eğer bu veritabanı aktif işlemdeyse (backup)
        if active_job and active_job['prod_db'] == dev_db.split("_dev_")[0]:
            conn = get_conn(PROD_SQL)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT session_id FROM sys.dm_exec_requests
                WHERE command = 'BACKUP DATABASE' AND DB_NAME(database_id) = ?
            """, dev_db.split("_dev_")[0])
            row = cursor.fetchone()
            if row:
                cursor.execute(f"KILL {row.session_id}")
                conn.close()
                active_jobs.pop(dev_db, None)
                return redirect(url_for('dashboard'))

        # 3. Bağlantıları sonlandırarak DROP
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
    prod_db = dev_db.split("_dev_")[0] if "_dev_" in dev_db else dev_db

    # 1. Prod sunucuda backup kontrolü
    try:
        conn = get_conn(PROD_SQL)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT percent_complete, command
            FROM sys.dm_exec_requests
            WHERE command = 'BACKUP DATABASE'
              AND (DB_NAME(database_id) = ? OR database_id IS NULL)
        """, prod_db)
        row = cursor.fetchone()
        conn.close()
        if row:
            return jsonify({
                "dev_db": dev_db,
                "stage": "backup",
                "percent_complete": int(row.percent_complete),
                "status": "running"
            })
    except:
        pass

    # 2. Dev sunucuda restore kontrolü (sql_text ile eşleşme yapılır)
    try:
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.percent_complete, r.command, DB_NAME(r.database_id) AS dbname, st.text AS sql_text
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
        print(f"[RESTORE ERROR] {e}")

    # Hiçbir işlem bulunamadıysa completed kabul et
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
