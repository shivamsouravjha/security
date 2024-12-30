#!/bin/bash
# Exit immediately if a command exits with a non-zero status
set -e

# Apply database migrations
echo "Running database migrations..."
python manage.py makemigrations file_app
python manage.py migrate

# Execute the container's main process (CMD)
echo "Starting Django server..."
exec "$@"
