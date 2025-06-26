from flask import Flask, request, jsonify
import pyodbc
import os

app = Flask(__name__)

# SQL bağlantı bilgileri
PROD_SQL = os.getenv("PROD_SQL_SERVER", "10.10.10.61")
DEV_SQL = os.getenv("DEV_SQL_SERVER", "172.35.10.29")
SQL_USER = os.getenv("SQL_USER", "devflask")
SQL_PASSWORD = os.getenv("SQL_PASSWORD", "StrongP@ss123")

# Dosya yolları
BACKUP_SHARE_PATH = os.getenv("BACKUP_SHARE_PATH", r"\\172.35.10.29\Backups")
DEV_DATA_PATH = os.getenv("DEV_DATA_PATH", r"D:\SQLData")

def get_conn(server_ip):
    conn = pyodbc.connect(
        f"DRIVER={{ODBC Driver 18 for SQL Server}};"
        f"SERVER={server_ip};UID={SQL_USER};PWD={SQL_PASSWORD};TrustServerCertificate=yes"
    )
    conn.autocommit = True
    return conn

# ✅ Backup + Restore işlemini başlatır
@app.route('/create', methods=['POST'])
def create_dev_db():
    data = request.json
    prod_db = data['prod_db']
    username = data['username']
    dev_db = f"{prod_db}_dev_{username}"

    bak_file = f"{BACKUP_SHARE_PATH}\\{prod_db}.bak"
    mdf_path = f"{DEV_DATA_PATH}\\{dev_db}.mdf"
    ldf_path = f"{DEV_DATA_PATH}\\{dev_db}_log.ldf"

    try:
        # STEP 1: BACKUP on PROD
        prod_conn = get_conn(PROD_SQL)
        prod_cursor = prod_conn.cursor()
        prod_cursor.execute(
            f"BACKUP DATABASE [{prod_db}] TO DISK = N'{bak_file}' WITH INIT"
        )
        while prod_cursor.nextset():
            pass
        prod_conn.close()

        # STEP 2: RESTORE on DEV
        dev_conn = get_conn(DEV_SQL)
        dev_cursor = dev_conn.cursor()
        dev_cursor.execute(f"""
            RESTORE DATABASE [{dev_db}]
            FROM DISK = N'{bak_file}'
            WITH MOVE '{prod_db}' TO N'{mdf_path}',
                 MOVE '{prod_db}_log' TO N'{ldf_path}',
                 REPLACE
        """)
        while dev_cursor.nextset():
            pass
        dev_conn.close()

        return jsonify({"status": "success", "dev_db": dev_db})

    except Exception as e:
        return jsonify({"status": "error", "message": repr(e)})

@app.route('/progress', methods=['GET'])
def check_backup_or_restore_progress():
    dev_db = request.args.get('dev_db')
    prod_db = dev_db.split('_dev_')[0] if '_dev_' in dev_db else dev_db

    try:
        # Check if dev DB exists
        check_conn = get_conn(DEV_SQL)
        check_cursor = check_conn.cursor()
        check_cursor.execute("SELECT COUNT(1) FROM sys.databases WHERE name = ?", dev_db)
        db_exists = check_cursor.fetchone()[0]
        check_conn.close()

        # Check BACKUP on prod SQL
        prod_conn = get_conn(PROD_SQL)
        prod_cursor = prod_conn.cursor()
        prod_cursor.execute("""
            SELECT percent_complete, status, start_time, command
            FROM sys.dm_exec_requests
            WHERE command = 'BACKUP DATABASE' AND DB_NAME(database_id) = ?
        """, prod_db)
        row = prod_cursor.fetchone()
        prod_conn.close()
        if row:
            return jsonify({
                "dev_db": dev_db,
                "stage": "backup",
                "percent_complete": float(row.percent_complete),
                "status": row.status,
                "start_time": str(row.start_time),
                "command": row.command
            })

        # Check RESTORE on dev SQL
        dev_conn = get_conn(DEV_SQL)
        dev_cursor = dev_conn.cursor()
        dev_cursor.execute("""
            SELECT percent_complete, status, start_time, command
            FROM sys.dm_exec_requests
            WHERE command = 'RESTORE DATABASE' AND DB_NAME(database_id) = ?
        """, dev_db)
        row = dev_cursor.fetchone()
        dev_conn.close()
        if row:
            return jsonify({
                "dev_db": dev_db,
                "stage": "restore",
                "percent_complete": float(row.percent_complete),
                "status": row.status,
                "start_time": str(row.start_time),
                "command": row.command
            })

        # Eğer DB hiç yoksa → işlem başlatılmamış
        if not db_exists:
            return jsonify({
                "dev_db": dev_db,
                "stage": "not_started",
                "percent_complete": 0,
                "status": "no_database"
            })

        # DB varsa ama aktif işlem yoksa → tamamlanmış
        return jsonify({
            "dev_db": dev_db,
            "stage": "completed",
            "percent_complete": 100,
            "status": "done"
        })

    except Exception as e:
        return jsonify({"status": "error", "message": repr(e)})

@app.route('/delete', methods=['POST'])
def delete_dev_db():
    data = request.json
    dev_db = data['dev_db']

    try:
        conn = get_conn(DEV_SQL)
        cursor = conn.cursor()

        # DB var mı kontrol et
        cursor.execute("SELECT COUNT(1) FROM sys.databases WHERE name = ?", dev_db)
        exists = cursor.fetchone()[0]

        if not exists:
            conn.close()
            return jsonify({
                "status": "not_found",
                "message": f"Database '{dev_db}' does not exist."
            })

        # DB varsa sil
        cursor.execute(f"DROP DATABASE [{dev_db}]")
        conn.close()
        return jsonify({
            "status": "success",
            "deleted_db": dev_db
        })

    except Exception as e:
        return jsonify({"status": "error", "message": repr(e)})

# ✅ Flask sunucusunu başlat
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
