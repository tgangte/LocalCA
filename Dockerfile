# Use the official Python image from the Docker Hub
FROM python:3.10

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory
WORKDIR /app

# Copy the requirements file into the container
COPY localca_project/requirements.txt /app/

# Install dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the entire project into the container
COPY localca_project /app/

# Run migrations
RUN python manage.py makemigrations LocalCA && \
    python manage.py migrate


#Create an admin superuser for the first time, if no user exists
RUN python manage.py initadmin
# Expose the port the app runs on
EXPOSE 8000

# Start the server
#RUN python manage.py runserver 0.0.0.0:8000
