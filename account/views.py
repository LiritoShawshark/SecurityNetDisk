import datetime
from django.conf import settings
from django.db.models import Q
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.http import HttpResponseRedirect
from django.http import FileResponse
from django.template import RequestContext
from django.urls import reverse
from django.utils.http import urlquote

# from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair

from .models import File
from .forms import UploadForm
import os

from django.core.signing import SignatureExpired
from django.http import HttpResponse
from django.urls import reverse
from django.views import View
from itsdangerous import Serializer
import json
from . import models
from . import forms
import hashlib
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import base64
from django.shortcuts import render
from django.shortcuts import redirect
# Create your views here.
import re
import datetime
import random
from django.conf import settings
import os
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair

Hash1pre = hashlib.md5
param_id = 'SS512'#对称双线性对
group = PairingGroup(param_id)#初始化双线性群

def Hash1(w,group):#md5哈希
    # 先对关键词w进行md5哈希
    hv = Hash1pre(str(w).encode('utf8')).hexdigest()
    # 再对md5值进行group.hash哈希，生成对应密文
    # 完整的Hash1由md5和group.hash组成
    hv = group.hash(hv, type=G1)
    return hv

def Setup(group):#生成密钥对 sk,pk

    # 代码符号G1 x G2 →  GT
    # 方案选用的是对称双线性对，故G2 = G1
    g = group.random(G1)#生成公共参数  g 和 alpha为生成元
    alpha = group.random(ZR)
    # 生成私钥与公钥并进行序列化
    sk = group.serialize(alpha)#序列化
    pk = [group.serialize(g), group.serialize(g ** alpha)]
    return [sk, pk]#私钥，公钥 pk:=[g,h=gα]和sk:=α


[sk, pk] = Setup(group)  # 生成密钥对
Hash2 = hashlib.sha256

def Enc(pk, w, group):#对搜索关键词用公钥加密，
    # 进行反序列化
    g, h = group.deserialize(pk[0]), group.deserialize(pk[1])
    r = group.random(ZR)
    t = pair(Hash1(w,group), h ** r)
    c1 = g ** r
    c2 = t
    # 对密文进行序列化
    return [group.serialize(c1), Hash2(group.serialize(c2)).hexdigest()]#c[0] c[1]以十六进制返回摘要

def TdGen(sk, w, group):#陷门生成 对要搜索的关键词加密
    sk = group.deserialize(sk)#sk反序列化
    td = Hash1(w,group) ** sk
    # 对陷门进行序列化
    return group.serialize(td)

def Test(td, c, group):#陷门和密文对比
    c1 = group.deserialize(c[0])
    c2 = c[1]
    #print("c2: "+c2)
    td = group.deserialize(td)
    return Hash2(group.serialize(pair(td, c1))).hexdigest() == c2



def Enc_search(key,w):

    c=Enc(pk,key,group)
    td=TdGen(sk,w,group)
    return Test(td,c,group)
    

the_salt = "my_salt"
root_path ="/home/admin/untitled/account/static/file/"


def home():
    return redirect('/index/')


def check(user):
    # 如下为加密后进入数据库的操作
    files = os.listdir(root_path + user.name)

    for f in files:
        if models.File.objects.filter(f_name=f).exists():
            continue

        file_size = os.path.getsize(
            root_path +
            user.name + "/" + f
        )

        [sk, pk] = Setup(group)
        f_type = re_match(f)
        enc_type = TdGen(sk, f_type, group)
        enc_type = enc_type.decode(encoding='utf-8')
        if (type(pk[0]) == bytes):  # 我也不太清楚为啥有时pk[0]的类型会变成str导致下面的编码不能进行
            pk[0] = pk[0].decode(encoding='utf-8')
        if (type(pk[1]) == bytes):
            pk[1] = pk[1].decode(encoding='utf-8')

        file_info = models.File()
        file_info.f_pk = json.dumps(pk)#使用json存储pk
        file_info.f_name = f
        file_info.sort = enc_type#文件类型加密
        file_info.f_size = file_size
        file_info.f_code = code()
        file_info.f_owner = user.name
        file_info.f_key = user.key
        file_info.f_url = root_path + user.name + "/" + f
        file_info.save()

        user.remain_space -= file_size
        user.point += 1
        user.save()

        key_bytes = user.key.encode('ascii')
        # 调用加密函数
        xor_enc(file_info.f_url, key_bytes)


def index(request): #主页
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')
    user = models.User.objects.get(name=user_name)
    check(user)
    user_name = request.session.get('user_name')
    file_infos = File.objects.filter(f_owner=user_name)
    used_space = user.max_space - user.remain_space
    scale = round(used_space/user.max_space, 2)
    scaling = scale * 100
    spaceprecent="%.2f%%" % (scale * 100)
    used = round(used_space/1048576, 2)
    max = round(user.max_space/1048576, 2)
    return render(request, 'account/index.html',{'file_infos': file_infos,'spaceprecent':spaceprecent,
                                                 'used':used,'max':max,'scaling':scaling})


def login(request):#登录
    if request.session.get('is_login',None):
        return redirect('/index/')

    if request.method == "POST":
        login_form=forms.UserForm(request.POST)
        message='请检查填写内容'
        if login_form.is_valid():#验证表单
           username=login_form.cleaned_data.get('username')
           password=login_form.cleaned_data.get('password')

           try:
               user=models.User.objects.get(name=username)
           except:
               message='用户不存在'
               return render(request,'account/login.html',locals())

           if not user.has_confirmed:
               message = '该用户还未经过邮件确认！'
               return render(request, 'login/login.html', locals())

           if user.password == password:#比对密码。
               request.session['is_login'] = True
               request.session['user_id'] = user.id
               request.session['user_name'] = user.name
               return redirect('/index/')
           else:
               message='密码不正确'
               return render(request,'account/login.html',locals())
        else:
           return render(request,'account/login.html',locals())
    login_form = forms.UserForm()#如果验证没有通过，可以返回一个空表单
    return render(request, 'account/login.html',locals())


def register(request):#注册
    if request.session.get('is_login', None):
        return redirect('/index/')

    if request.method == 'POST':
        register_form = forms.RegisterForm(request.POST)
        message = "请检查填写的内容！"
        if register_form.is_valid():
            username = register_form.cleaned_data.get('username')
            password1 = register_form.cleaned_data.get('password1')
            password2 = register_form.cleaned_data.get('password2')
            email = register_form.cleaned_data.get('email')
            sex = register_form.cleaned_data.get('sex')
            key = get_md5(username)
            if re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", email) == None:
                message = '邮箱格式错误'#正则匹配邮箱格式，错误则返回提示信息
                return render(request, 'account/register.html', locals())
            if len(str(password1)) < 6:
                message = '密码长度不得小于6位啊亲'
                return render(request, 'account/register.html', locals())
            elif password1 != password2:
                message = '两次输入的密码不同！'
                return render(request, 'account/register.html', locals())
            else:
                same_name_user = models.User.objects.filter(name=username)
                if same_name_user:
                    message = '用户名已经存在'
                    return render(request, 'account/register.html', locals())
                same_email_user = models.User.objects.filter(email=email)
                if same_email_user:
                    message = '该邮箱已经被注册了！'
                    return render(request, 'account/register.html', locals())
                # 发邮件

                new_user = models.User()
                new_user.name = username
                new_user.password = password1
                new_user.email = email
                new_user.sex = sex
                new_user.key = key  # 构造成员信息
                new_user.file_url = root_path + username
                new_user.save()
                if not os.path.exists(new_user.file_url):
                   os.makedirs(new_user.file_url)                           # 创建自己的文件夹
                request.session['user_name'] = new_user.name
                code = make_confirm_string(new_user)
                send_email(email, code)
                message = '请前往邮箱进行确认！'
                return render(request, 'account/confirm.html', locals())
        else:
            return render(request, 'account/register.html', locals())
    register_form = forms.RegisterForm()
    return render(request, 'account/register.html', locals())


def changepwd(request):#修改密码
    if not request.session.get('is_login', None):
        return redirect('/login/')

    if request.method == 'POST':
        changepwd_form = forms.ChangepwdForm(request.POST)
        message = "请检查填写的内容！"
        if changepwd_form.is_valid():
            password_old = changepwd_form.cleaned_data.get('password_old')
            email = changepwd_form.cleaned_data.get('email')
            password_new = changepwd_form.cleaned_data.get('password_new')
            password_new2 = changepwd_form.cleaned_data.get('password_new2')


            if len(str(password_new)) < 6:
                message = '密码长度不得小于6位啊亲'
                return render(request, 'account/changepwd.html', locals())

            elif password_new != password_new2:
                message = '两次输入的密码不同！'
                return render(request, 'account/changepwd.html', locals())

            else:
                changer_name = request.session.get('user_name')
                user = models.User.objects.get(name=changer_name)
                if user.email != email:
                    message = '您的邮箱错误！'
                    return render(request, 'account/changepwd.html', locals())
                if user.password != password_old:
                    message = '原密码错误！'
                    return render(request, 'account/changepwd.html', locals())
                # 发邮件
                user.password = password_new
                user.save()
                return redirect('/login/')
        else:
            return render(request, 'account/changepwd.html', locals())
    changepwd_form = forms.ChangepwdForm()
    return render(request, 'account/changepwd.html', locals())


def logout(request):#登出
    if not request.session.get('is_login', None):
        return redirect("/login/")
    request.session.flush()
    return redirect("/login/")


def get_md5(the_string): #md5加密用户名作为用户密钥
        the_string_with_salt = the_string + the_salt
        the_md5 = hashlib.md5()
        the_md5.update(the_string_with_salt.encode('utf-8'))
        the_string_md5 = the_md5.hexdigest()
        return the_string_md5


def xor_enc(file_path, key):#xor加密文件
    picRead = open(file_path, "rb")
    picData=picRead.read()
    picLen=len(picData)

    f_write = open(root_path + '1', "wb")

    keyData = key
    keyLen = keyData.__len__()
    #获取Key
    key=picLen // keyLen * keyData + keyData[:picLen%keyLen]
    #进行循环加密
    for i in range(len(key)):
       newByte = key[i] ^ picData[i]
       #写出二进制文件
       f_write.write(bytes([newByte]))
    f_write.close()
    picRead.close()

    # 将处理好的文件返回至file_path
    os.remove(file_path)

    mov_read = open(root_path + "1", "rb")
    mov_write = open(file_path, "wb")

    mov_write.write(mov_read.read())

    mov_read.close()
    mov_write.close()

    os.remove(root_path + "1")


def make_confirm_string(user):#构造注册时的邮箱确认码
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    code = hash_code(user.name, now)
    models.ConfirmString.objects.create(code=code, user=user,)
    return code


def send_email(email, code):#注册时的邮箱确认邮件发送函数

    from django.core.mail import EmailMultiAlternatives

    subject = '来自<<Secure NetDisk>>的注册确认邮件'

    text_content = '''感谢注册<<Secure NetDisk>>，\
                    如果你看到这条消息，说明你的邮箱服务器不提供HTML链接功能，请联系管理员！'''

    html_content = '''
                    <p>感谢注册Secure NetDisk,\
                    这里是<a href="http://{}/confirm/?code={}" target=blank>激活入口</a>！</p>
                    <p>请点击激活入口完成注册确认！</p>
                    <p>此链接有效期为7天！</p>
                    '''.format('127.0.0.1:8000', code, settings.CONFIRM_DAYS)

    msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_HOST_USER, [email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()


def user_confirm(request): #用户确认页面
    code = request.GET.get('code', None)
    message = ''
    try:
        confirm = models.ConfirmString.objects.get(code=code)
    except:
        message = '无效的确认请求!'
        return render(request, 'account/confirm.html', locals())

    c_time = confirm.c_time
    now = datetime.datetime.now()
    if now > c_time + datetime.timedelta(settings.CONFIRM_DAYS):
        confirm.user.delete()
        message = '您的邮件已经过期！请重新注册!'
        return render(request, 'account/confirm.html', locals())
    else:
        confirm.user.has_confirmed = True
        confirm.user.save()
        confirm.delete()
        message = '感谢确认，请使用账户登录！'
        return render(request, 'account/confirm.html', locals())


def hash_code(s, salt='mysite'): #用来复制构造确认码
    h = hashlib.sha256()
    s += salt
    h.update(s.encode())
    return h.hexdigest()


def code():#构造文件分享的提取码
    list_num = [1,2,3,4,5,6,7,8,9,0]
    list_str = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','s','t','x','y','z']
    veri_str = random.sample(list_str,2)
    veri_num = random.sample(list_num,2)
    veri_out = random.sample(veri_num + veri_str,4)
    veri_res = str(veri_out[0]) + str(veri_out[1]) + str(veri_out[2]) + str(veri_out[3])
    return veri_res


def forget(request):#忘记密码

    if request.method == 'POST':
        forget_form = forms.ForgetForm(request.POST)
        message = "请检查填写的内容！"
        if forget_form.is_valid():
            username = forget_form.cleaned_data.get('username')
            email = forget_form.cleaned_data.get('email')
            if not models.User.objects.filter(name=username).exists():
                message = '用户名不存在'
                return render(request, 'account/forget.html', locals())
            user = models.User.objects.get(name=username)
            if email != user.email:
                message = '邮箱错误'
                return render(request, 'account/forget.html', locals())
            new_password = password()
            user.password = new_password
            user.save()
            send_email_forget(email,new_password)
            message = '请前往邮箱进行确认！'
            return render(request, 'account/confirm.html', locals())
        else:
            return render(request, 'account/forget.html', locals())
    forget_form = forms.ForgetForm()
    return render(request, 'account/forget.html', locals())


def send_email_forget(email, password):#忘记密码时重置密码的邮件发送函数

    from django.core.mail import EmailMultiAlternatives

    subject = '来自<<Secure NetDisk>>的密码重置邮件'

    text_content = '''感谢使用<<Secure NetDisk>>，\
                    如果你看到这条消息，说明你的邮箱服务器不提供HTML链接功能，请联系管理员！'''

    html_content = '''
                    <p>感谢使用Secure NetDisk,\
                    这里是<a href="http://{}/login" target=blank>登录入口</a>！</p>
                    <p>检查到您的账户刚刚进行了密码重置,</p>
                    <p>您更改后的有效密码是{}</p>
                    '''.format('127.0.0.1:8000', password,settings.CONFIRM_DAYS)

    msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_HOST_USER, [email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()


def password():#构造六位临时密码
    list_num = [1,2,3,4,5,6,7,8,9,0]
    list_str = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','s','t','x','y','z']
    veri_str = random.sample(list_str,3)
    veri_num = random.sample(list_num,3)
    veri_out = random.sample(veri_num + veri_str,6)
    veri_res = str(veri_out[0]) + str(veri_out[1]) + str(veri_out[2]) + str(veri_out[3]) + str(veri_out[4]) + str(veri_out[5])
    return veri_res


def re_match(filename):#匹配文件类型的正则
    regex_photo = re.compile(r'^.*\.(jpg|jpeg|png|gif|tif|bmp)$')
    regex_pdf = re.compile(r'^.*\.(pdf)$')
    regex_txt = re.compile(r'^.*\.(txt)$')

    if regex_photo.search(filename):
        return "photo"
    elif regex_pdf.search(filename):
        return "PDF"
    elif regex_txt.search(filename):
        return "TXT"
    else:
        return "others"


def upload_file(request): # 文件上传
    user = models.User.objects.get(name=request.session.get('user_name'))
    if request.method == 'GET':               # 进入文件上传的初始页面
        user = models.User.objects.get(name=request.session.get('user_name'))
        used_space = user.max_space - user.remain_space
        scale = round(used_space / user.max_space, 2)
        scaling = scale * 100
        spaceprecent = "%.2f%%" % (scale * 100)
        used = round(used_space / 1048576, 2)
        max = round(user.max_space / 1048576, 2)
        return render(request, 'account/upload.html', locals())

    elif request.method == 'POST': # 请求方法为POST时，进行处理
        file_name = request.POST.get('filename')  # 获得文件名
        dir = root_path + file_name            # 创建上传空间
        if not os.path.isdir(dir):
            os.makedirs(dir)
        file_count = request.POST.get('blobname')                   # 获得的包的标识
        file = request.FILES.get('file')

        destination = open(os.path.join(dir, str(file_count)), 'wb+')  # 打开特定的文件进行二进制的写操作

        for chunk in file.chunks():  # 分块写入文件
            destination.write(chunk)
        destination.close()

        if request.POST.get("lastone"):                    # 得到最后一个包的操作

            # 如下为文件拼接操作
            num = int(request.POST.get("lastone"))         # 获取总包数

            # 创建文件进行拼接
            fp = open(root_path + user.name + "/" + file_name, "ab+")

            # 拼接
            for i in range(0, num+1):
                handle = open(dir + "/" + str(i), "rb")
                fp.write(handle.read())
                handle.close()

            # 关闭fp
            fp.close()


            return HttpResponse('1')
        return HttpResponse('2')
    return HttpResponse('3')


def photo(request):#图片类型页面
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')

    # file_infos = File.objects.filter(Q(sort="photo") & Q(f_owner=user_name))
    file_list = File.objects.filter(f_owner=user_name)
    file_infos = []
    for a_file in file_list:
        key = "photo"
        pk = json.loads(a_file.f_pk)
        pk[0] = pk[0].encode(encoding='gb18030')
        pk[1] = pk[1].encode(encoding='gb18030')
        c_key = Enc(pk, key, group)  # 对要搜索的关键词加密
        td = a_file.sort.encode(encoding='gb18030')
        if Test(td, c_key, group):
            file_infos.append(a_file)

    user = models.User.objects.get(name=user_name)
    used_space = user.max_space - user.remain_space
    scale = round(used_space / user.max_space, 2)
    scaling = scale * 100
    spaceprecent = "%.2f%%" % (scale * 100)
    used = round(used_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    return render(request, 'account/photo.html', {'file_infos': file_infos, 'spaceprecent': spaceprecent,
                                                  'used': used, 'max': max,'scaling': scaling})


def pdf(request):#pdf类型页面
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')

    # file_infos = File.objects.filter(Q(sort="PDF") & Q(f_owner=user_name))
    file_list = File.objects.filter(f_owner=user_name)
    file_infos = []
    for a_file in file_list:
        key = "PDF"
        pk = json.loads(a_file.f_pk)
        pk[0] = pk[0].encode(encoding='gb18030')
        pk[1] = pk[1].encode(encoding='gb18030')
        c_key = Enc(pk, key, group)  # 对要搜索的关键词加密
        td = a_file.sort.encode(encoding='gb18030')
        if Test(td, c_key, group):
            file_infos.append(a_file)

    user = models.User.objects.get(name=user_name)
    used_space = user.max_space - user.remain_space
    scale = round(used_space / user.max_space, 2)
    scaling = scale * 100
    spaceprecent = "%.2f%%" % (scale * 100)
    used = round(used_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    return render(request, 'account/pdf.html', {'file_infos': file_infos, 'spaceprecent': spaceprecent,
                                                'used': used, 'max': max, 'scaling': scaling})


def txt(request):#txt类型页面
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')

    # file_infos = File.objects.filter(Q(sort="TXT") & Q(f_owner=user_name))
    file_list = File.objects.filter(f_owner=user_name)
    file_infos = []
    for a_file in file_list:
        key = "TXT"
        pk = json.loads(a_file.f_pk)
        pk[0] = pk[0].encode(encoding='gb18030')
        pk[1] = pk[1].encode(encoding='gb18030')
        c_key = Enc(pk, key, group)  # 对要搜索的关键词加密
        td = a_file.sort.encode(encoding='gb18030')
        if Test(td, c_key, group):
            file_infos.append(a_file)

    user = models.User.objects.get(name=user_name)
    used_space = user.max_space - user.remain_space
    scale = round(used_space / user.max_space, 2)
    scaling = scale * 100
    spaceprecent = "%.2f%%" % (scale * 100)
    used = round(used_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    return render(request, 'account/txt.html', {'file_infos': file_infos, 'spaceprecent': spaceprecent,
                                                'used': used, 'max': max, 'scaling': scaling})


def others(request):#其他类型页面
    if not request.session.get('is_login', None):
        return redirect('/login/')
    user_name = request.session.get('user_name')

    # file_infos = File.objects.filter(Q(sort="others") & Q(f_owner=user_name))
    file_list = File.objects.filter(f_owner=user_name)
    file_infos = []
    for a_file in file_list:
        key = "others"
        pk = json.loads(a_file.f_pk)
        pk[0] = pk[0].encode(encoding='gb18030')
        pk[1] = pk[1].encode(encoding='gb18030')
        c_key = Enc(pk, key, group)  # 对要搜索的关键词加密
        td = a_file.sort.encode(encoding='gb18030')
        if Test(td, c_key, group):
            file_infos.append(a_file)

    user = models.User.objects.get(name=user_name)
    used_space = user.max_space - user.remain_space
    scale = round(used_space / user.max_space, 2)
    scaling = scale * 100
    spaceprecent = "%.2f%%" % (scale * 100)
    used = round(used_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    return render(request, 'account/others.html', {'file_infos': file_infos, 'spaceprecent': spaceprecent,
                                                   'used': used, 'max': max, 'scaling': scaling})


def download(request, id):#下载页面
    file_info = File.objects.get(id=id)
    file_owner=file_info.f_owner
    user=models.User.objects.get(name=file_owner)
    print('下载的文件名：' + file_info.f_name)
    xor_enc(file_info.f_url, user.key.encode('ascii'))
    file = open(file_info.f_url, 'rb')
    response = FileResponse(file)
    response['Content-Disposition'] = 'attachment;filename="%s"' % urlquote(file_info.f_name)
    xor_enc(file_info.f_url, user.key.encode('ascii'))
    return response


def delete(request, id):# 删除文件
    file_info = File.objects.get(id=id)
    size=file_info.f_size
    try:
        os.remove(file_info.f_url)
    except:
        pass
    file_info.delete()
    file_infos = File.objects.all()
    file_owner_name = request.session.get('user_name')
    user = models.User.objects.get(name=file_owner_name)
    old_remain_space=user.remain_space
    user.remain_space=old_remain_space+size
    user.save()
    return HttpResponseRedirect('/index')


def shareFile(request,id):#文件分享
    sharefile = File.objects.get(id=id)
    owner = sharefile.f_owner
    if request.method == "POST":
        sharefile_form=forms.SharefileForm(request.POST)
        message='请检查填写内容'

        if sharefile_form.is_valid():#验证表单
            code = sharefile_form.cleaned_data.get('code')
            if sharefile.f_code != code:
                message = '提取码错误！'
                return render(request,'account/share.html',{"id":id,"message":message,
                                                            "sharefile_form":sharefile_form,
                                                            "owner":owner})
            else:
                return redirect('/download/'+id)
        else:
            return render(request, 'account/share.html',{"id":id,
                                                         "message":message,
                                                         "sharefile_form":sharefile_form,
                                                         "owner":owner})
    sharefile_form = forms.SharefileForm()  # 如果验证没有通过，可以返回一个空表单
    return render(request, 'account/share.html',{"id":id,
                                                 "sharefile_form":sharefile_form,
                                                 "owner":owner})


def add_space(request):
    user=user=models.User.objects.get(name=request.session['user_name'])#获取当前登录人员信息
    used_space = user.max_space - user.remain_space
    scale = round(used_space / user.max_space, 2)
    scaling = scale * 100
    spaceprecent = "%.2f%%" % (scale * 100)
    used = round(used_space / 1048576, 2)
    max = round(user.max_space / 1048576, 2)
    now_ponits=user.point
    if request.method=='GET':
        try:
          points=int(request.GET.get('addspace'))
          #积分数判断。
          if points<0 :
             message='积分参数错误'
             return render(request,'account/add_space.html',locals())
          elif points>user.point or points==0:
             message='积分不够'
             return render(request,'account/add_space.html',locals())
          elif 0<points<=user.point:
             addspace_number=points*pow(2,20)*10
             now_space=addspace_number+user.max_space
            #最终的空间大小不能超过4GB
             if now_space >2147483648*2:
                message='超过最大上限'
                return  render(request,"account/add_space.html",locals())
             else:
                message='空间申请成功'
                mess=addspace_number
                user.max_space=now_space
                user.remain_space=user.remain_space+addspace_number
                user.point=user.point-points
                user.save()
                now_ponits=user.point
                used_space = user.max_space - user.remain_space
                scale = round(used_space / user.max_space, 2)
                scaling = scale * 100
                spaceprecent = "%.2f%%" % (scale * 100)
                used = round(used_space / 1048576, 2)
                max = round(user.max_space / 1048576, 2)

                return render(request, "account/add_space.html", locals())
        except :
            return render(request,"account/add_space.html",locals())

    return render(request,"account/add_space.html",locals())


def search(request):
    if request.method=='GET':
        key_word=request.GET['key']
        user_name = request.session.get('user_name')

        #file_infos = File.objects.filter(Q(f_name__icontains=key_word) & Q(f_owner=user_name))
        file_list = File.objects.filter(f_owner=user_name)
        file_infos = []
        for a_file in file_list:
            key = key_word.encode('gb18030')#统一编码
            name=a_file.f_name.encode('gb18030')
            lenght1=len(key)
            lenght2=len(name)
            for i in range(lenght1,lenght2+1):
                w_key=name[i-lenght1:i]#截取文件名片段一一匹对
                if Enc_search(key, w_key):#如果检索到 则将对应文件加入列表并跳出循环
                   file_infos.append(a_file)
                   break

        user = models.User.objects.get(name=user_name)
        used_space = user.max_space - user.remain_space
        scale = round(used_space / user.max_space, 2)
        scaling = scale * 100
        spaceprecent = "%.2f%%" % (scale * 100)
        used = round(used_space / 1048576, 2)
        max = round(user.max_space / 1048576, 2)
        return render(request,'account/index.html',locals())