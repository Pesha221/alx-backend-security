# __init__.py (in project root)
from .celery import app as celery_app

__all__ = ('celery_app',)
