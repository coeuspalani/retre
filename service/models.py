from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# User Profile
class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('general', 'General User'),
        ('creator', 'ML Project Creator'),
        ('admin', 'Administrator'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = models.ImageField(default='profile_pic/default.png', upload_to='profile_pic/')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='general')

    def __str__(self):
        return f"{self.user.username} - {self.role} | {self.image}"


# ML Project
class MLProject(models.Model):
    creator = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='projects')
    project_name = models.CharField(max_length=200)
    project_thumbnail = models.ImageField(default='project_thumbnail/default.png', upload_to='project_thumbnail/')
    requirements = models.TextField(blank=True, help_text="List required packages or dependencies")
    description = models.TextField()
    is_approved = models.BooleanField(default=False)
    submitted_at = models.DateTimeField(default=timezone.now)


    def __str__(self):
        return f"Project ID: {self.id} Project NAME: {self.project_name} by {self.creator.user.username}"


# Multiple Project Files
class MLProjectFile(models.Model):
    project = models.ForeignKey(MLProject, on_delete=models.CASCADE, related_name='files')
    submitted_att = models.DateTimeField(default=timezone.now)
    project_file = models.FileField(upload_to='ml_projects/')

    def __str__(self):
        return f"File for project: {self.project.project_name}"
