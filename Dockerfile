FROM python:3.11-bullseye

WORKDIR /app

COPY . .

RUN apt-get update && \
    apt-get install -y curl gnupg apt-transport-https gcc g++ && \
    curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    curl https://packages.microsoft.com/config/debian/11/prod.list > /etc/apt/sources.list.d/mssql-release.list && \
    apt-get update && \
    ACCEPT_EULA=Y DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --allow-downgrades --allow-change-held-packages \
    msodbcsql18 unixodbc unixodbc-dev libodbc1 odbcinst \
    -o Dpkg::Options::="--force-overwrite" && \
    pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "run.py"]
