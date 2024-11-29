'''
This module contains the command to initialize the admin user if no users exist.
'''
import logging
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.db.utils import IntegrityError


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    '''
    This class contains the command to initialize the admin user if no users exist. It is run each time docker starts up a build.
    '''
    help = "Creates a default superuser (admin) if no users exist"

    def handle(self, *args, **options):
        if User.objects.count() == 0:
            username = "admin"
            password = "password"
            email = "admin@example.com"

            try:
                admin = User.objects.create_superuser(
                    username=username, email=email, password=password
                )
                logger.info("Default superuser created: %s", admin)

                self.stdout.write(
                    self.style.SUCCESS(
                        f"Default superuser created:\n"
                        f"Username: {username}\n"
                        f"Password: {password}\n"
                        f"Please change the password immediately!"
                    )
                )

                logger.info("Default superuser was created")

            except IntegrityError:
                self.stdout.write(
                    self.style.ERROR(
                        "Error creating default superuser. User might already exist."
                    )
                )
                logger.error("Failed to create default superuser")

        else:
            self.stdout.write(
                self.style.WARNING(
                    "Default superuser can only be initialized if no users exist"
                )
            )
            logger.warning(
                "Attempted to create default superuser when users already exist"
            )
