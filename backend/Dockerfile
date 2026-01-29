FROM python:3.11-slim

# set workdir
WORKDIR /usr/src/app

# system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

# copy
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# make entrypoint executable and fix line endings
RUN dos2unix ./entrypoint.sh && chmod +x ./entrypoint.sh

ENV FLASK_APP=app
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/usr/src/app

EXPOSE 5000

# default entrypoint - runs gunicorn
CMD ["./entrypoint.sh"]