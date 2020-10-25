from django.shortcuts import render
from django.http import HttpResponse,JsonResponse
# Create your views here.

def index(request):

    #return JsonResponse({'user':'Hello World!'})
    return render(request,'index.html',{'content':'hello django!'})
