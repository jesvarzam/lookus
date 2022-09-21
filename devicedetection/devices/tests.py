from django.test import TestCase
from django.contrib.auth.models import User

class DevicesTestCase(TestCase):
    
    def setUp(self):
        User.objects.create_user(username='testinguser', password='testingpass123')
    
    def tearDown(self) -> None:
        return super().tearDown()
    
    #Should add new device being authenticated, it should redirect to devices list page
    def test_should_add_new_device(self):
        self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testingpass123'})
        response = self.client.post('/devices/add/', {'device_name': '127.0.0.1'}, follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/devices/list/')
        
    #Should not add new device being unauthenticated, it should redirect to login page
    def test_should_not_add_new_device_unauthenticated(self):
        response = self.client.post('/devices/add/', {'device_name': 'test'}, follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/authentication/sign_in/')

    #Should not add new device with invalid format, it should redirect to adding new device form
    def test_should_not_add_new_device_invalid_format(self):
        self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testingpass123'})
        response = self.client.post('/devices/add/', {'device_name': 'invalidformat'}, follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/devices/add/')