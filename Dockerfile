# syntax=docker/dockerfile:1

FROM python:3.11-slim as base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    PATH="/usr/local/bin:$PATH"

WORKDIR /code

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    libgeos-dev \
    libproj-dev \
    gdal-bin \
    gettext \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/ requirements/

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements/production.txt

COPY . .

RUN groupadd -r django && useradd -r -g django django
RUN chown -R django:django /code

USER django

ENV DJANGO_SETTINGS_MODULE=authloc.settings

COPY ./compose/production/start /start
COPY ./compose/production/start-celeryworker /start-celeryworker
COPY ./compose/production/start-celerybeat /start-celerybeat
RUN chmod +x /start /start-celeryworker /start-celerybeat

EXPOSE 8000

CMD ["/start"]
