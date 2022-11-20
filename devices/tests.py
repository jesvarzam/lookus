from django.test import TestCase
from django.contrib.auth.models import User

class DevicesTestCase(TestCase):
    
    def setUp(self):
        User.objects.create_user(username='testinguser', password='testingpass123')
    
    def tearDown(self) -> None:
        return super().tearDown()

    def test_should_access_devices_view(self):
        self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testingpass123'})
        response = self.client.get('/devices/list/', follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/devices/list/')
        self.assertTrue('Aún no tienes ningún dispositivo añadido' in response.content.decode('utf-8'))
    
    #Should add new device being authenticated, it should redirect to devices list page
    def test_should_add_new_device(self):
        self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testingpass123'})
        response = self.client.post('/devices/add/', {'device_name': '127.0.0.1'}, follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/devices/list/')

    def test_should_list_added_device(self):
        self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testingpass123'})
        response = self.client.post('/devices/add/', {'device_name': '127.0.0.1'}, follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/devices/list/')
        self.assertTrue('Dispositivo(s) añadido(s) correctamente' in response.content.decode('utf-8'))
        self.assertTrue('127.0.0.1' in response.content.decode('utf-8'))
        
    def test_should_not_add_new_device_unauthenticated(self):
        response = self.client.post('/devices/add/', {'device_name': 'test'}, follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/authentication/sign_in/')

    def test_should_not_add_new_device_invalid_format(self):
        self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testingpass123'})
        response = self.client.post('/devices/add/', {'device_name': 'invalidformat'}, follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/devices/add/')
        self.assertTrue('El formato del dispositivo o de alguno de los dispositivos no es correcto, debe ser una dirección IP o una URL' in response.content.decode('utf-8'))


    def test_should_remove_device(self):
        self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testingpass123'})
        self.client.post('/devices/add/', {'device_name': '127.0.0.1'})
        response = self.client.post('/devices/remove/1/', follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/devices/list/')
        self.assertTrue('127.0.0.1' not in response.content.decode('utf-8'))