from django.db import models

import uuid

# Create your models here.
class User(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4(),
        editable=False
    )
    name = models.CharField(max_length=100)
    age = models.IntegerField()
    gender = models.CharField(
        max_length=100,
        choices=(
            ('Male', 'Male'),
            ('Female', 'Female'),
            ('Others', 'Others'),
        )
    )
    email = models.EmailField()
    type = models.CharField(
        max_length=100,
        choices=(
            ('admin', 'admin'),
            ('teacher', 'teacher'),
            ('student', 'student'),
            ('guest', 'guest')
        )
    )
    password = models.CharField(
        max_length=500,
        default=None
    )
