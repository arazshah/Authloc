# Authloc – Location-Based Authentication Platform

Authloc is a production-ready Django 5 project that blends traditional authentication with geospatial context. It ships with a PostGIS-backed PostgreSQL database, Redis caching, Celery workers, REST API with JWT authentication, and Docker-based deployment tooling.

## Features

* __Location-aware authentication__: store trusted locations and capture login attempts with geospatial metadata.
* __Custom user model__: `authentication.User` extends Django’s user with location fields.
* __PostGIS support__: `locations` app uses `PointField` for geo data, enabling radius-based checks.
* __RESTful API__: built on Django REST Framework, secured with JWT (SimpleJWT + dj-rest-auth).
* __Asynchronous processing__: Celery with Redis handles background tasks, scheduling via `django-celery-beat`.
* __Security hardening__: Django Axes, CORS/CSR security headers, and configurable rate limits.
* __Comprehensive settings__: environment-driven configuration split across base and environment modules.
* __Dockerized infrastructure__: `docker-compose.yml` orchestrates PostgreSQL/PostGIS, Redis, Django, Celery worker, and beat services.

## Project Structure

```text
Authloc/
├── authloc/                 # Django project package
│   ├── settings/            # Modular settings (base.py, development.py, etc.)
│   ├── celery.py            # Celery application
│   ├── urls.py
│   ├── asgi.py / wsgi.py
│   └── __init__.py
├── authentication/          # Custom user model & auth-related logic
├── core/                    # Shared abstract models & utilities
├── locations/               # Trusted locations & verification models
├── permissions/             # Placeholder for permission logic
├── audit/                   # Placeholder for audit logging
├── compose/production/      # Production entrypoint scripts
├── requirements/            # Requirements split (base, development, production)
├── docker-compose.yml       # Local development and deployment stack
├── Dockerfile               # Production image build
├── manage.py
└── README.md
```

## Prerequisites

* Docker and Docker Compose (recommended path)
* Alternatively: Python 3.11, Postgres 15 with PostGIS 3.3+, Redis 7+

## Quick Start (Docker)

1. __Clone & configure__
   ```bash
   git clone <your-repo-url>
   cd Authloc
   cp .env.example .env
   ```
   Update `.env` with secure values (e.g., `DJANGO_SECRET_KEY`, DB credentials, allowed hosts).

2. __Launch services__
   ```bash
   docker compose up --build
   ```
   This pulls PostGIS and Redis images, builds the Django image, runs migrations, collects static files, seeds an optional superuser, and starts the API on `http://localhost:8000`.

3. __Access the app__
   * API root / admin panel: `http://localhost:8000/`
   * Admin dashboard: `http://localhost:8000/admin/`
   * Celery worker logs: `docker compose logs -f celery_worker`

4. __Stop services__
   ```bash
   docker compose down
   ```

## Local Development (without Docker)

1. __Install system deps__ (Ubuntu example):
   ```bash
   sudo apt-get update
   sudo apt-get install python3.11 python3.11-venv python3.11-dev \
        build-essential libpq-dev gdal-bin libgdal-dev libproj-dev libgeos-dev \
        redis-server postgresql postgresql-15-postgis-3
   ```

2. __Create virtual environment__
   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements/development.txt
   ```

3. __Configure environment__
   ```bash
   cp .env.example .env
   # Update DATABASE_URL to point to your local Postgres/PostGIS instance
   ```

4. __Prepare database__
   ```bash
   createdb authloc
   psql -d authloc -c "CREATE EXTENSION IF NOT EXISTS postgis;"
   ```

5. __Apply migrations & run server__
   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   python manage.py runserver 0.0.0.0:8000
   ```

6. __Start Celery worker & beat__ (each in its own shell):
   ```bash
   celery -A authloc worker -l INFO
   celery -A authloc beat -l INFO
   ```

## Management Commands

```bash
python manage.py makemigrations        # create new migrations
python manage.py migrate               # apply migrations
python manage.py createsuperuser       # bootstrap admin user
python manage.py collectstatic         # prepare static assets
python manage.py shell_plus            # with django-extensions (dev)
```

## Celery Tasks

* Worker start: `celery -A authloc worker -l INFO`
* Beat scheduler: `celery -A authloc beat -l INFO`
* Test task (example):
  ```bash
  python manage.py shell -c "from authloc.celery import debug_task; debug_task.delay()"
  ```

## Testing & Quality

```bash
pytest --ds=authloc.settings.development
flake8
black --check .
isort --check-only .
```

Enable `pre-commit` locally:
```bash
pre-commit install
``` 

## API Documentation

* Schema endpoint: `/api/schema/`
* Swagger UI (via drf-spectacular): `/api/schema/swagger-ui/`
* ReDoc: `/api/schema/redoc/`

Authentication is JWT-based. Acquire tokens via dj-rest-auth JWT endpoints (e.g., `/api/auth/login/`) and send `Authorization: Bearer <token>` headers.

## Environment Variables

All runtime configuration lives in `.env`. The included `.env.example` lists commonly used settings:

* __Django__: `DJANGO_SECRET_KEY`, `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`
* __Database__: `DATABASE_URL`, `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD`
* __Redis__: `REDIS_URL`, `CELERY_BROKER_URL`
* __JWT__: `JWT_ACCESS_TOKEN_LIFETIME`, `JWT_AUTH_COOKIE`
* __Security__: `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `REFERRER_POLICY`
* __Email__: `EMAIL_BACKEND`, `DEFAULT_FROM_EMAIL`

Tailor these to your environment before deployment.

## Deployment

* __Dockerfile__ builds a Python 3.11 slim image with system libraries for PostGIS.
* __compose/production/start__ collects static files, runs migrations, and starts Gunicorn.
* For production orchestration:
  * Run `docker compose -f docker-compose.yml up -d django celery_worker celery_beat`
  * Configure reverse proxy (e.g., Nginx/Traefik) to handle SSL and route traffic to Django.
* Set `DJANGO_ENV=production`, `DJANGO_DEBUG=False`, and tighten security headers in `.env`.

## Logs

* Application logs write to `logs/authloc.log` and stdout.
* Adjust log levels via `DJANGO_LOG_LEVEL` in `.env`.

## Database Migrations & Admin Access

* Run `python manage.py migrate` (Docker does this automatically on startup).
* Create superuser with `python manage.py createsuperuser` or populate `DJANGO_SUPERUSER_*` variables before container start.
* Admin panel lives at `/admin/` and uses the custom `authentication.User` model.

## Troubleshooting

* __PostGIS errors__ – ensure the `postgis/postgis` image initialized, or manually run `CREATE EXTENSION postgis;`.
* __Redis connection issues__ – verify `redis` service is healthy (`docker compose ps`).
* __Celery tasks not running__ – confirm Celery worker and beat containers are up and share the same `.env`.
* __Static files missing__ – run `python manage.py collectstatic` and ensure `STATIC_ROOT` is mounted/persisted.

## License

Specify your project license here (MIT, Apache-2.0, etc.).
