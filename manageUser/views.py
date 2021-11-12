from django.http import HttpResponse, JsonResponse
from django.shortcuts import render

from pydantic import BaseModel, ValidationError, validator

from .models import User

import bcrypt
import jwt

class userModal(BaseModel):
    name: str
    age: int
    gender: str
    email: str
    type: str
    password: str
    confirmPassword: str

    @validator('name')
    def checkName(cls, name):
        if len(name) == 0:
            raise ValueError("Name must be exist.")

        return name

    @validator('email')
    def checkEmail(cls, email):
        if len(email) == 0:
            raise ValueError("Email must be exist.")

        user = User.objects.filter(email=email)
        
        if user.exists() == True:
            raise ValueError("Email already exist.")
        
        return email

    @validator('type')
    def checkType(cls, type):
        if len(type) == 0:
            raise ValueError("Type must be exist.")
        
        return type

    @validator('confirmPassword')
    def checkConfirmPassword(cls, confirmPassword, values, **kwargs):
        if(len(confirmPassword) > 6 or len(confirmPassword) < 6):
            raise ValueError("Confirm password must be six characters.")

        if 'password' in values and values['password'] != confirmPassword:
            raise ValueError("Confirm password must be match with password.")

        return confirmPassword

    @validator('password')
    def checkPassword(cls, password):
        if(len(password) < 6 or len(password) > 6):
            raise ValueError("Password must be six characters.")
        
        return password

def addUsers(request):
    if request.method == 'POST':
        token = request.headers

        if 'Authorization' in token:
            token = token['Authorization'].split(' ')[1]

            try:
                payload = jwt.decode(token, 'secret', algorithms=["HS256", ])

                if payload['type'] != 'admin':
                    return JsonResponse({"message": "Admin can only create an user."})

                try:
                    name = request.POST['name']
                    age = request.POST['age']
                    gender = request.POST['gender']
                    email = request.POST['email']
                    userType = request.POST['userType']
                    password = request.POST['password']
                    confirmPassword = request.POST['confirmPassword']
                except Exception as e:
                    return JsonResponse({ "message": str(e) + " must be need."})

                try:
                    user = userModal(
                        name = name,
                        age = age,
                        gender = gender,
                        email = email,
                        type = userType,
                        password = password,
                        confirmPassword = confirmPassword
                    )
                except ValidationError as e:
                    return HttpResponse(str(e))

                password = b'' + password.encode()
                hashed = bcrypt.hashpw(password, bcrypt.gensalt())

                userSave = User(
                    name = name,
                    age = age,
                    gender = gender,
                    email = email,
                    type = userType,
                    password = hashed
                )
                userSave.save()
                return JsonResponse({"message": "Success"})
            except:
                return JsonResponse({"message": "Token mismatch."})
        else:
            return JsonResponse({"message": "Token not found."})
    else:
        return render(request, 'add.html')

def listUsers(request):
    token = request.headers
    
    if 'Authorization' in token:
        token = token['Authorization'].split(' ')[1]
        try:
            jwt.decode(token, 'secret', algorithms=["HS256", ])

            users = list(User.objects.values())

            if len(users) > 0:
                return JsonResponse(users, safe=False)
            else:
                return HttpResponse("No user found.")
        except:
            return HttpResponse("Token mismatch.")
    else:
            return HttpResponse("Token not found.")

def listPage(request):
    return render(request, 'list.html')

def updateUser(request):
    if request.method == "POST":
        token = request.headers

        if 'Authorization' in token:
            token = token['Authorization'].split(' ')[1]
            payload = jwt.decode(token, 'secret', algorithms=["HS256", ])

            name = request.POST['name']
            gender = request.POST['gender']
            age = request.POST['age']
            id = request.POST['id']

            user = User.objects.filter(id=id).values()[0]

            if payload['type'] != 'admin' and payload['type'] != 'teacher':
                return JsonResponse({ "message": "Admin or teacher can only update an user."})
            
            if payload['type'] == 'teacher' and user['type'] != 'student':
                return JsonResponse({"message":"Teacher can only update student details."})

            User.objects.filter(id=id).update(name=name, gender=gender, age=age)

            return JsonResponse({"message": "Success"})
        else:
            return JsonResponse({"message": "Token mismatch"})

def updateUsers(request, id):
    user = User.objects.filter(id=id).values()[0]
    return render(request, 'update.html', { "content": { "name": user['name'], "age": user['age'], "gender": user['gender'], "id": user['id'] } })

def deleteUsers(request):
    id = request.POST['id']
    token = request.headers

    if 'Authorization' in token:
        token = token['Authorization'].split(' ')[1]
        try:
            payload = jwt.decode(token, 'secret', algorithms=["HS256", ])
            try:
                if payload['type'] != 'admin':
                    return JsonResponse({"message": "Admin can delete."})

                record = User.objects.get(id=id)
                record.delete()

                return JsonResponse({"message": "User deleted"})
            except:
                return JsonResponse({"message": "User not exist"})
        except:
            return JsonResponse({"message": "Token mismatch."})
    else:
        return JsonResponse({"message": "Token not found."})

def createAdmin(self):
    password = '123456'
    password = b'' + password.encode()
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    user = User(name='Rajeev', age=23, gender='Male', email='rajeevkolappuram@gmail.com', type='admin', password=hashed)
    user.save()
    return HttpResponse("Admin created.")

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        password = b'' + password.encode()

        user = User.objects.filter(email=email).values()
        
        if(len(user) == 0):
            return JsonResponse({"message": "User not found."})
        else:
            userPassword = b'' + user[0]['password'].split("'")[1].encode()

            if bcrypt.checkpw(password, userPassword):
                userType = user[0]['type']
                encoded_jwt = jwt.encode({"email": email, "type": userType}, "secret", algorithm="HS256")

                return JsonResponse({"message": "user logged", "token": encoded_jwt})
            else:
                return JsonResponse({"message": "Password mismatch."})
    else:
        return render(request, 'login.html')
