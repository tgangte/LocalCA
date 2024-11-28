# LocalCA
Local Certificate Authority 



### Development steps
```

python -m venv venv
source venv/bin/activate
cd localca_project
pip install -r requirements.txt
python manage.py makemigrations LocalCA

python manage.py migrate

python manage.py createsuperuser
python manage.py runserver
```
