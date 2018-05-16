from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import User, Description, Message, Comment
import bcrypt

def index(request):
    return render(request, 'dashboard/index.html')

def signin(request):
    # renders a page that allows user to sign in
    return render(request, 'dashboard/signin.html')

def signin_process(request):
    # validates sign in
    # redirects to admin or user dashboard
    errors = User.objects.validator_signin(request.POST)
    if len(errors):
        for key, value in errors.items():
            messages.error(request, value)
            print ("*"*150, "something went wrong")
        return redirect('/signin')
    else:
        user = User.objects.get(email=request.POST['email'])
        request.session['first_name'] = user.first_name
        request.session['last_name'] = user.last_name
        request.session['email'] = user.email

        # messages.success(request, "User successfully logged in")

        if user.user_level == "admin":
            return redirect('/dashboard/admin')
        else:
            return redirect('/dashboard')


def register(request):
    # renders a page that allows users to register
    return render(request, 'dashboard/register.html')

def register_process(request):
    # validates registration
    # redirects to sign in page
    errors = User.objects.validator_register(request.POST)
    if len(errors):
        for key, value in errors.items():
            messages.error(request, value)
        print ("*"*150, errors)
        return redirect('/register')
    else:
        # bcrypt
        hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        # is it first person to register?
        database = User.objects.all()
        if len(database) < 1:
            user_level = "admin"
        else:
            user_level = "normal"
        print('*'*150, "user level:", user_level)

        user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=hash, user_level=user_level)
        user.save()
        # request.session['first_name'] = request.POST['first_name']
        messages.success(request, "Account successfully registered")
        return redirect('/signin')


def dash_admin(request):
    # renders a page that shows admin dashboard
    context = {
        'users': User.objects.all(),
        'signed_in_user': User.objects.filter(email=request.session['email'])
    }
    return render(request, 'dashboard/dash_admin.html', context)

def new(request):
    # allows admin to create new user
    return render(request, 'dashboard/new.html')

def new_process(request):
    errors = User.objects.validator_register(request.POST)
    if len(errors):
        for key, value in errors.items():
            messages.error(request, value)
        return redirect('/users/new')
    else:
        # bcrypt
        hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        # is it first person to register?
        user_level = "normal"

        user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=hash, user_level=user_level)
        user.save()
        # request.session['first_name'] = request.POST['first_name']
        messages.success(request, "New user successfully added")
        return redirect('/dashboard/admin')


def edit(request, id):
    # renders a page that allows admin to edit users
    context = {
        'user': User.objects.get(id=id),
    }
    return render(request, 'dashboard/edit.html', context)


def edit_process(request, id):
    # validates edit
    if request.POST['info_to_process'] == "user_info":
        print('*'*150, "into info_to_process")
        errors = User.objects.validator_edit_user(request.POST)
        if len(errors):
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/users/edit/'+id)
        else:
            user = User.objects.get(id=id)
            user.first_name = request.POST['first_name']
            user.last_name = request.POST['last_name']
            user.email = request.POST['email']
            user.user_level = request.POST['user_level']
            user.save()
            messages.success(request, "User successfully edited")
            return redirect('/dashboard/admin')
    elif request.POST['info_to_process'] == "user_password":
        errors = User.objects.validator_update_pw(request.POST)
        if len(errors):
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/users/edit/'+id)
        else:
            user = User.objects.get(id=id)
            hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            user.password = hash
            user.save()
            messages.success(request, "Password successfully updated")
            return redirect('/dashboard/admin')


def delete(request, id):
    # deletes user from database
    User.objects.get(id=id).delete()
    messages.success(request, "User deleted")
    return redirect('/dashboard/admin')


def show(request, id):
    # shows user info and wall
    description = []
    try:
        desc = Description.objects.get(user=id)
        description.append(desc)
    except:
        description = []
    if len(description) < 1:
        context = {
            'user': User.objects.get(id=id),
            'messages': Message.objects.filter(written_to=id),
            'comments': Comment.objects.all(),
            'signed_in_user': User.objects.filter(email=request.session['email']),
        }
    else:
        context = {
            'user': User.objects.get(id=id),
            'messages': Message.objects.filter(written_to=id),
            'comments': Comment.objects.all(),
            'signed_in_user': User.objects.filter(email=request.session['email']),
            'description': Description.objects.get(user=id)
        }
    if User.objects.filter(email=request.session['email'])[0].user_level == "admin":
        return render(request, 'dashboard/show.html', context)
    else:
        return render(request, 'dashboard/show_user.html', context)


def post_message(request, id):
    user_signed_in = User.objects.get(email=request.session['email'])
    user_written_to = User.objects.get(id=id)
    Message.objects.create(message=request.POST['message'], written_by=user_signed_in, written_to=user_written_to).save()
    return redirect('/users/show/'+id)

def post_comment(request, id):
    user_signed_in = User.objects.get(email=request.session['email'])
    message_replied_to = request.POST['replied_to']
    replied_to = Message.objects.get(id=message_replied_to)
    Comment.objects.create(comment=request.POST['comment'], replied_to=replied_to, commented_by=user_signed_in).save()
    return redirect('/users/show/'+id)


def dash(request):
    # renders user dashboard page
    context = {
        'users': User.objects.all(),
        'signed_in_user': User.objects.filter(email=request.session['email'])
    }
    return render(request, 'dashboard/dash.html', context)


def user_edit(request, id):
    # renders a page that allows users to edit
    context = {
        'user': User.objects.get(id=id),
    }
    return render(request, 'dashboard/user_edit.html', context)

def user_edit_process(request, id):
    # validates user edit
    if request.POST['info_to_process'] == "user_info":
        print('*'*150, "into info_to_process")
        errors = User.objects.validator_edit_user(request.POST)
        if len(errors):
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/users/user_edit/'+id)
        else:
            user = User.objects.get(id=id)
            user.first_name = request.POST['first_name']
            user.last_name = request.POST['last_name']
            user.email = request.POST['email']
            user.save()
            messages.success(request, "User successfully edited")
            return redirect('/dashboard')
    elif request.POST['info_to_process'] == "user_password":
        errors = User.objects.validator_update_pw(request.POST)
        if len(errors):
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/users/user_edit/'+id)
        else:
            user = User.objects.get(id=id)
            hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            user.password = hash
            user.save()
            messages.success(request, "Password successfully updated")
            return redirect('/dashboard')
    elif request.POST['info_to_process'] == "description":
        description = []
        try:
            desc = Description.objects.get(user=User.objects.get(id=id))
            description.append(desc)
        except:
            description = []
        if len(description) >= 1:
            Description.objects.get(user=User.objects.get(id=id)).content = request.POST['description']
        else:
            Description.objects.create(content=request.POST['description'], user=User.objects.get(id=id)).save()
        messages.success(request, "User info successfully updated")
        return redirect('/dashboard')


def logout(request):

    return redirect('/')
