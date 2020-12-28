from django.utils import timezone

from django.db import models
# Create your models here.
class User(models.Model):
     gender=(
         ('male','男'),
         ('female','女'),
     )


     name = models.CharField(max_length=16,unique=True)
     password = models.CharField(max_length=128)
     email = models.EmailField(unique=True)#邮箱
     sex = models.CharField(max_length=32, choices=gender, default="男")
     c_time = models.DateTimeField(auto_now_add=True)#注册时间
     crypto_id = models.CharField(max_length=32, default="MD5")  # 通过该值选择对应的加密算法
     key = models.CharField(max_length=1024)  # 要使用的密钥
     file_url = models.CharField(max_length=256,default="127.0.0.1:8000/static/file")#文件真实存储路径
     has_confirmed = models.BooleanField(default=False)#标志是否验证
     max_space = models.BigIntegerField(default=2147483648)#最大存储空间单位B，默认值为2GB
     remain_space = models.BigIntegerField(default=2147483648)#剩余存储空间单位B，默认值为2GB
     point = models.IntegerField(default=5)#积分，通过下载上传文件获得，一积分10MB



     def __str__(self):
        return self.name

     class Meta:
         ordering = ["-c_time"]
         verbose_name = "people"
         verbose_name_plural = "people"


class File(models.Model):
      f_pk = models.CharField(max_length=256, default="1")
      # 文件真实存储路径
      f_name = models.CharField(max_length=16, unique=False,default="1")
      f_owner = models.CharField(max_length=16, unique=False,default="1")
      f_size = models.BigIntegerField(default=0)
      f_code = models.CharField(default="1234", max_length=4)
      f_key = models.CharField(max_length=1024, default=None)
      f_url = models.CharField(max_length=256, default="127.0.0.1:8000/static/file")
      sort = models.CharField(max_length=256, default="others")
      upload_time = models.DateTimeField(default=timezone.now())

def __str__(self):
        return self.f_name

class Meta:
        #ordering = ["-c_time"]
        verbose_name = "file"
        verbose_name_plural = "file"

class ConfirmString(models.Model):
    code = models.CharField(max_length=256)
    user = models.OneToOneField('User', on_delete=models.CASCADE)
    c_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.name + ":   " + self.code

    class Meta:

        ordering = ["-c_time"]
        verbose_name = "确认码"
        verbose_name_plural = "确认码"



