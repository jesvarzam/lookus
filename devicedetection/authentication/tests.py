from django.test import TestCase
from django.contrib.auth.models import User
from .views import validate

class AuthenticationTestCase(TestCase):

    def setUp(self):
        return super().setUp()
    
    def tearDown(self):
        return super().tearDown()
    
    def test_should_be_valid_user_for_registration(self):
        username = "testinguser"
        password = "testingpass123"
        confirmed_password = "testingpass123"
        self.assertEquals(validate(username, password, confirmed_password), '')
    
    def test_should_register_previous_user(self):
        # User.objects.create_user("testinguser", "testingpass123").save()
        response = self.client.post('/authentication/sign_up/', {'username': 'testinguser', 'password1': 'testingpass123', 'password2': 'testingpass123'}, follow=True)
        self.assertEquals("testinguser", User.objects.get(username='testinguser').username)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/')
    
    def test_should_not_be_valid_for_registration_1(self):
        #Validation failed because username length is greater than 20 characters
        username = "testingusertestingusertestingusertestinguser"
        password = "testingpass123"
        confirmed_password = "testingpass123"
        self.assertEquals(validate(username, password, confirmed_password), 'El usuario debe ser menor a 20 caracteres')
    
    def test_should_not_be_valid_for_registration_2(self):
        #Validation failed because there is an existing user with same username
        self.client.post('/authentication/sign_up/', {'username': 'testinguser', 'password1': 'testingpass123', 'password2': 'testingpass123'})
        username = "testinguser"
        password = "testingpass123"
        confirmed_password = "testingpass123"
        self.assertEquals(validate(username, password, confirmed_password), 'Ya existe un usuario con ese nombre')

    def test_should_not_be_valid_for_registration_3(self):
        #Validation failed because password length is lower than 8 characters
        username = "testinguser"
        password = "pass"
        confirmed_password = "pass"
        self.assertEquals(validate(username, password, confirmed_password), 'La contraseña debe tener un mínimo 8 caracteres, y al menos una letra y un número')

    def test_should_not_be_valid_for_registration_4(self):
        #Validation failed because password does not contain at least one character
        username = "testinguser"
        password = "12345678"
        confirmed_password = "12345678"
        self.assertEquals(validate(username, password, confirmed_password), 'La contraseña debe tener un mínimo 8 caracteres, y al menos una letra y un número')

    def test_should_not_be_valid_for_registration_5(self):
        #Validation failed because password does not contain at least one digit
        username = "testinguser"
        password = "testingpass"
        confirmed_password = "testingpass"
        self.assertEquals(validate(username, password, confirmed_password), 'La contraseña debe tener un mínimo 8 caracteres, y al menos una letra y un número')

    def test_should_not_be_valid_for_registration_6(self):
        #Validation failed because password and confirmed_password are not the same
        username = "testinguser"
        password = "testingpass123"
        confirmed_password = "testingpass1234"
        self.assertEquals(validate(username, password, confirmed_password), 'Las contraseñas deben ser iguales')

    
    def test_should_login(self):
        User.objects.create_user(username='testinguser', password='testingpass123')
        response = self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testingpass123'}, follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/')

    
    def test_should_not_login_1(self):
        #Should not login because inexistent user
        response = self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testingpass123'}, follow=True)
        self.assertEquals(response.wsgi_request.path, '/authentication/sign_in/')

    
    def test_should_not_login_2(self):
        #Should not login because bad credentials
        User.objects.create_user(username='testinguser', password='testingpass123')
        response = self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testingpass'}, follow=True)
        self.assertEquals(response.wsgi_request.path, '/authentication/sign_in/')


    def test_should_logout_after_login(self):
        response = self.client.post('/authentication/sign_up/', {'username': 'testinguser', 'password1': 'testingpass123', 'password2': 'testingpass123'}, follow=True)
        self.assertEquals("testinguser", User.objects.get(username='testinguser').username)
        self.assertEquals(response.wsgi_request.path, '/')
        response = self.client.get('/authentication/log_out/', follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/authentication/sign_in/')