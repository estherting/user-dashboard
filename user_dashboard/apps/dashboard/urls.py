from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^signin$', views.signin),
    url(r'signin/process', views.signin_process),
    url(r'^register$', views.register),
    url(r'^register/process$', views.register_process),
    url(r'^dashboard/admin$', views.dash_admin),
    url(r'^users/new$', views.new),
    url(r'^users/new/process$', views.new_process),
    url(r'^users/edit/(?P<id>\d+)$', views.edit),
    url(r'^users/edit/(?P<id>\d+)/process$', views.edit_process),
    url(r'^users/delete/(?P<id>\d+)$', views.delete),
    url(r'^users/show/(?P<id>\d+)$', views.show),
    url(r'^users/(?P<id>\d+)/post_message$', views.post_message),
    url(r'^users/(?P<id>\d+)/post_comment$', views.post_comment),
    url(r'^dashboard$', views.dash),
    url(r'^users/user_edit/(?P<id>\d+)$', views.user_edit),
    url(r'^users/user_edit/(?P<id>\d+)/process', views.user_edit_process),
    url(r'^logout$', views.logout),
]
