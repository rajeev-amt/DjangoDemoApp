from django.urls import path

from . import views

urlpatterns = [
    path('create', views.addUsers, name='create-users'),
    path('list', views.listUsers, name='list-user'),
    path('admin', views.createAdmin, name='create-first-admin'),
    path('update/<str:id>', views.updateUsers, name='update-users'),
    path('delete', views.deleteUsers, name='delete-users'),
    path('login', views.login, name='login'),
    path('listPage', views.listPage, name='list-page'),
    path('updateUser', views.updateUser, name='update-user'),
]
