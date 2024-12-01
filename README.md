# LocalCA
Local Certificate Authority 



### Development steps
```
cd localca_project
python -m venv venv
source venv/bin/activate
cd localca_project
pip install -r requirements.txt
python manage.py makemigrations LocalCA

python manage.py migrate

python manage.py initadmin

python manage.py runserver
```

## Deploy with pre-build docker image from docker hub 

Create docker-compose.yml file any empty directory with the following content:

```
services:
  web:
    image: practicalsre/local-ca:latest
    container_name: web
    restart: unless-stopped
    volumes:
      - db:/app/db
      - static_volume:/app/staticfiles
    networks:
      - app_network
    command: >
      sh -c "
        ls -l
        python manage.py migrate &&
        python manage.py initadmin &&
        python manage.py collectstatic --noinput &&
        exec gunicorn localca_project.wsgi --bind 0.0.0.0:8000 --worker-class=gthread --threads=4"
  nginx:
    image: practicalsre/local-ca-nginx:latest
    container_name: nginx
    restart: unless-stopped
    ports:
      - "80:80"
    volumes:
      - static_volume:/app/staticfiles:ro
    depends_on:
      - web
    networks:
      - app_network

volumes:
  static_volume:
  db: 

networks:
  app_network:
    driver: bridge
```
And the run the following command to start the services:

```
sudo docker pull 
sudo docker compose up   # to start the services
sudo docker compose down # to stop the services
```

#Local build and deploy with docker

```
git clone this repo

cd into  the directory that contains the docker-compose.yml file
sudo docker compose up --build

```
