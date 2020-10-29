# Create your views here.
from django.shortcuts import render
from django.db import models
from .models import User
from django.http import HttpResponse,JsonResponse,HttpRequest,HttpResponseBadRequest
import json
import logging
import simplejson
import jwt,bcrypt,datetime
from django.conf import settings


FORMAT= "%(asctime)s %(threadName)s %(thread)d %(message)s"
logging.basicConfig(format=FORMAT,level=logging.INFO)
print(settings.SECRET_KEY)


AUTH_EXPIRE = 8*60*60

def authenticate(view):
    def wrapper(request:HttpResponse):
        payload = request.META.get('HTTP_JWT')
        if not payload:
            return HttpResponse(status=401)
        try:
            payload = jwt.decode(payload,settings.SECRET_KEY,algorithms=['HS256'])
            print(payload)
        except:
            return HttpResponse(status=401)

        try :
            user_id = payload.get('user_id',-1)
            user = User.objects.filter(pk=user_id).get()
            request.user = user #如果正确，则注入user
            print('-'*30)
        except Exception as e:
            print(e)
            return HttpResponse(status=401)

        ret = view(request)
        return ret
    return wrapper


def index(request):
    #return JsonResponse({'user':'Hello World!'})
    return render(request,'index.html',{'content':'hello django!'})

def get_token(user_id):
    return jwt.encode(
        {
            'user_id':user_id,
            'exp':int(datetime.datetime.now().timestamp()) + AUTH_EXPIRE,
            'timestamp':int(datetime.datetime.now().timestamp())
        },settings.SECRET_KEY,'HS256'
    ).decode()

def reg(request):
    try:
        payload = simplejson.loads(request.body)
        email = payload['email']
        query = User.objects.filter(email=email)
        if query:
            return HttpResponseBadRequest()

        name = payload['name']
        password = bcrypt.hashpw(payload['password'].encode(),bcrypt.gensalt())
        print(email,name,password)

        user=User()
        user.email=email
        user.name=name
        user.password=password

        try:
            user.save()
            return JsonResponse({'token':get_token(user.id)})
        except:
            raise
    except Exception as e:
        logging.info(e)
        return HttpResponseBadRequest()


def login(request):
    payload = simplejson.loads(request.body)
    try:
        email = payload['email']
        user = User.objects.filter(email=email).get()

        if bcrypt.checkpw(payload['password'].encode(),user.password.encode()):
            # 验证通过
            token = get_token(user.id)
            print(token)
            res = JsonResponse(
                {
                    'uiser':{
                        'user_id':user.id,
                        'name':user.name,
                        'email':user.email
                    },
                    'token':token
                }
            )
            res.set_cookie('JWT',token)
            return res
        else:
            return HttpResponseBadRequest()

    except Exception as e:
        print(e)
        return HttpResponseBadRequest()



