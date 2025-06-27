# Dev DB Manager

Bu proje MS SQL veritabanlarının yedeklenip geliştirme ortamına kopyalanmasını ve sorguların web arayüzü üzerinden yönetilmesini sağlar.

## Kurulum

1. Gerekli paketleri yüklemek için:

```bash
pip install -r requirements.txt
```

2. Uygulamayı başlatmak için:

```bash
python run.py
```

veya Docker kullanmak isterseniz:

```bash
docker-compose up --build
```

## Ortam Değişkenleri

Aşağıdaki değişkenler `.env` dosyası kullanılarak veya sistem ortam değişkeni olarak ayarlanabilir. Değer verilmediğinde kod içindeki varsayılanlar kullanılır.

| Değişken            | Açıklama                                   | Varsayılan |
| ------------------- | ------------------------------------------ | ---------- |
| `SECRET_KEY`        | Flask oturum anahtarı                      | `your-secret-key` |
| `LDAP_SERVER`       | LDAP sunucu adresi                         | `ldap://10.0.0.201` |
| `LDAP_DOMAIN`       | LDAP domain ismi                           | `BAYLAN` |
| `PROD_SQL_SERVER`   | Üretim SQL sunucusu IP'si                  | `10.10.10.61` |
| `DEV_SQL_SERVER`    | Geliştirme SQL sunucusu IP'si              | `172.35.10.29` |
| `SQL_USER`          | SQL sunucularına bağlanacak kullanıcı adı  | `devflask` |
| `SQL_PASSWORD`      | SQL kullanıcısının şifresi                 | `StrongP@ss123` |
| `BACKUP_SHARE_PATH` | Üretim yedeğinin kaydedileceği paylaşımlı klasör | `\\172.35.10.29\Backups` |
| `DEV_DATA_PATH`     | Geliştirme sunucusunda .mdf/.ldf dosyalarının tutulacağı klasör | `D:\SQLData` |
| `WAZUH_SYSLOG_HOST` | (Opsiyonel) Wazuh syslog sunucu adresi     | `127.0.0.1` |
| `WAZUH_SYSLOG_PORT` | (Opsiyonel) Wazuh syslog portu             | `514` |
| `WAZUH_SYSLOG_PREFIX` | (Opsiyonel) Syslog mesajı ön eki          | (boş) |

## Yapılandırma Dosyaları

`config/` klasöründe kullanıcı yetkileri ve SQL sunucuları gibi bilgiler JSON/TXT dosyalarında tutulur. Uygulama çalışırken bu dosyaları okur.

- `allowed_users.txt` – Giriş yapabilecek kullanıcılar
- `admin_users.txt` – Yönetici yetkisine sahip kullanıcılar
- `sql_servers.json` – Sunucu takma adları ve IP adresleri
- `user_permissions.json` – Kullanıcı bazında erişilebilecek veritabanları
- `query_log.txt` – Çalıştırılan sorguların kaydı

Bu dosyalar Docker kullanıyorsanız `./config` klasörü konteynıra bağlanarak kullanılabilir.

## Testler

Projede `pytest` kullanılarak birim testleri yazılmıştır. Testleri çalıştırmak için:

```bash
pytest -q
```

Bağımlılıkların kurulu olduğundan emin olun.

## Yapılandırma Güncellemesi

`user_permissions.json` dosyasında her kullanıcı için yeni `allow_query` alanı eklenmiştir. Eski dosyaları uyumlu hale getirmek için her kullanıcı nesnesine bu anahtar eklenmelidir:

```json
{
  "kullanici": {
    "allow_query": true,
    "main": ["OrnekDB"]
  }
}
```

Anahtar eksik olduğunda uygulama varsayılan olarak `true` kabul eder ancak yetkiyi kapatabilmek için dosyanın güncellenmesi gerekir.
