# Use the official Python image from the Docker Hub, slim version
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt /app/

# Install dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the entire project into the container
COPY localca_project /app/

# Expose the port the app runs on
EXPOSE 8000

# Start the server, this is handled in docker-compose.yml
#RUN python manage.py runserver 0.0.0.0:8000
