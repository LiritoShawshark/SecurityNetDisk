from django.urls import path

from . import views

urlpatterns=[
    path('index/',views.index),
    path('login/',views.login),
    path('register/',views.register),
    path('logout/',views.logout),
    path('confirm/', views.user_confirm),
    path('forget/', views.forget),
    path('upload/', views.upload_file),
    path('photo/', views.photo),  # 列表
    path('pdf/', views.pdf),
    path('txt/', views.txt),
    path('changepwd/', views.changepwd),
    path('others/', views.others),
    path('download/<id>', views.download, name='download'),  # 下载
    path('delete/<id>', views.delete, name='delete'), # 删除
    path('share/<id>', views.shareFile, name='share'),
    path('add_space/',views.add_space),#增加存储空间
    path('search/',views.search),
]