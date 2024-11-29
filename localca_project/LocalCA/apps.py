'''
This module contains the configuration for the LocalCA application.
'''

from django.apps import AppConfig


class LocalcaConfig(AppConfig):
    '''
    This class represents the LocalCA application.
    '''
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'LocalCA'
