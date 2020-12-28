from django import forms
#from captcha.fields import CaptchaField

class UserForm(forms.Form):
    username = forms.CharField(label="用户名", max_length=128,
                               widget=forms.TextInput(attrs={'class':'form-control','placeholder':"用户名",'name':"username", 'id':"uname"}))
    password = forms.CharField(label="密码", max_length=256, 
                                widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':"密码",'name':"password1", 'id':"pwd"}) )
 #   captcha = CaptchaField(label='验证码')

class RegisterForm(forms.Form):
    gender = (
        ('male', "男"),
        ('female', "女"),
    )
    username = forms.CharField(label="用户名", max_length=128,
                               widget=forms.TextInput(attrs={'class':'form-control','placeholder':"用户名",'name':"username", 'id':"uname"}))
    password1 = forms.CharField(label="密码", max_length=256,
                                widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':"密码",'name':"password1", 'id':"pwd"}))
    password2 = forms.CharField(label="确认密码", max_length=256,
                                widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':"确认密码",'name':"password2", 'id':"pwd2"}))
    email = forms.EmailField(label="邮箱地址",
                             widget=forms.EmailInput(attrs={'class':'form-control','placeholder':"E.G: 123@123.com",'name':"email", 'id':"email"}))
    sex = forms.ChoiceField(label='性别', choices=gender)

#class UploadFileForm(forms.Form):
   # title = forms.CharField(max_length=50)
   # file = forms.FileField()
class UploadForm(forms.Form):
    file = forms.FileField(
        widget=forms.ClearableFileInput(attrs={'multiple': True}),  # 支持多文件上传
        label='选择文件...',
        help_text='最大100M'
    )


# class Addspace(forms.Form):
#     gender=(
#         ('KB','KB'),
#         ('GB','GB'),
#     )
#     space_number=forms.IntegerField(label='空间大小',max_value=2147483648)
#     space_unit=forms.ChoiceField(label='单位', choices=gender)
#     space=forms.CharField(label='空间',max_length=256)

class ForgetForm(forms.Form):

    username = forms.CharField(label="用户名", max_length=128,
                            widget=forms.TextInput(attrs={'class':'form-control','placeholder':"用户名",'name':"username", 'id':"uname"}))
    email = forms.EmailField(label="邮箱地址", 
                            widget=forms.TextInput(attrs={'class':'form-control','placeholder':"用户名",'name':"username", 'id':"uname"}))

class ChangepwdForm(forms.Form):
    password_old = forms.CharField(label="旧密码", max_length=256,
                              widget=forms.TextInput(attrs={'class':'form-control','placeholder':"用户名",'name':"username", 'id':"uname"}))
    email = forms.EmailField(label="邮箱", 
                            widget=forms.TextInput(attrs={'class':'form-control','placeholder':"用户名",'name':"username", 'id':"uname"}))
    password_new = forms.CharField(label="新密码", max_length=256,
                          widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':"密码",'name':"password1", 'id':"pwd"}))
    password_new2 = forms.CharField(label="确认密码", max_length=256,
                           widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':"密码",'name':"password1", 'id':"pwd"}))

class SharefileForm(forms.Form):
    code = forms.CharField(label="提取码", max_length=5)