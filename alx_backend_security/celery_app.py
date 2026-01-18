# celery.py (create in project root)
import os
from celery import Celery

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project.settings')

# Create Celery app
app = Celery('your_project')

# Load task modules from all registered Django apps
app.autodiscover_tasks()

# Configure from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
    
