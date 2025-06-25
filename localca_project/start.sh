#!/bin/sh

# Run Django commands
python manage.py makemigrations LocalCA
python manage.py migrate
python manage.py initadmin
python manage.py collectstatic --noinput

# Start Gunicorn
exec gunicorn localca_project.wsgi --bind 0.0.0.0:8000 --worker-class=gthread --threads=4
