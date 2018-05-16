from __future__ import unicode_literals
from django.db import models
import bcrypt

class UserManager(models.Manager):
    def validator_register(self, postData):
        errors = {}
        if len(postData['first_name']) < 2:
            errors['first_name'] = "First name should be at least 2 characters"
        if len(postData['last_name']) < 2:
            errors['last_name'] = "Last name should be at least 2 characters"
        if not postData['first_name'].isalpha() or not postData['last_name'].isalpha():
            errors['name'] = "First and Last name should contain letters only"
        if User.objects.filter(email=postData['email']):
            errors['email'] = "Email is already registered"
        if len(postData['email']) < 1:
            errors['email'] = "Email is required"
        valid_e = False
        for c in postData['email']:
            if c == "@":
                valid_e = True
        if not valid_e:
            errors['email'] = "Email must be a valid email"
        if len(postData['password']) < 8:
            errors['password'] = 'Password must be at least 8 characters long'
        if postData['password'] != postData['confirm_pw']:
            errors['password'] = "Password and Confirm password must match"
        return errors

    def validator_signin(self, postData):
        # validates for login:
        errors = {}
        if postData['email']:
            try:
                user = User.objects.get(email=postData['email'])
                if not user:
                    errors['login'] = "Unable to login"
                elif not bcrypt.checkpw(postData['password'].encode(), user.password.encode()):
                    errors['login'] = "Unable to login"
            except:
                errors['login'] = "Unable to login"
        else:
            errors['login'] = "Unable to login"
        return errors

    def validator_edit_user(self, postData):
        errors = {}
        if len(postData['first_name']) < 2:
            errors['first_name'] = "First name should be at least 2 characters"
        if len(postData['last_name']) < 2:
            errors['last_name'] = "Last name should be at least 2 characters"
        if not postData['first_name'].isalpha() or not postData['last_name'].isalpha():
            errors['name'] = "First and Last name should contain letters only"
        if len(postData['email']) < 1:
            errors['email'] = "Email is required"
        valid_e = False
        for c in postData['email']:
            if c == "@":
                valid_e = True
        if not valid_e:
            errors['email'] = "Email must be a valid email"
        return errors

    def validator_update_pw(self, postData):
        errors = {}
        if len(postData['password']) < 8:
            errors['password'] = 'Password must be at least 8 characters long'
        if postData['password'] != postData['confirm_pw']:
            errors['password'] = "Password and Confirm password must match"
        return errors



class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    user_level = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

class Description(models.Model):
    content = models.TextField()
    user = models.OneToOneField(User, primary_key=True)

class Message(models.Model):
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    written_by = models.ForeignKey(User, related_name="messages_wrote")
    written_to = models.ForeignKey(User, related_name="messages_received")

class Comment(models.Model):
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    replied_to = models.ForeignKey(Message, related_name="comments_received")
    commented_by = models.ForeignKey(User, related_name="comments_wrote")
