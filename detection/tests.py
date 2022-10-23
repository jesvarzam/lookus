from django.test import TestCase
from django.contrib.auth.models import User
from devices.models import Device

class DetectionTestCase(TestCase):


    def setUp(self) -> None:
        User.objects.create_user(username='testinguser', password='testinguser123')
        self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testinguser123'}, follow=True)
        response = self.client.post('/devices/add/', {'device_name': '127.0.0.1'}, follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertTrue('127.0.0.1' in response.content.decode('utf-8'))
    

    def tearDown(self) -> None:
        return super().tearDown()
    

    def test_should_detect_added_device(self):
        device_id = Device.objects.get(name='127.0.0.1').id
        response = self.client.post('/detection/detect/{}/'.format(device_id), follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertTrue('El dispositivo 127.0.0.1 se ha detectado correctamente' in response.content.decode('utf-8'))
        self.assertTrue(Device.objects.get(id=device_id).detected)

    
    def test_should_not_detect_inexistent_device(self):
        response = self.client.post('/detection/detect/5/', follow=True)
        self.assertEquals(response.status_code, 404)
        self.assertEquals(response.content.decode('utf-8'), 'ERROR 404: No tienes ningún dispositivo añadido con ese id')
    

    def test_should_not_detect_device_from_another_user(self):
        admin = User.objects.create_user(username='admin', password='admin123')
        Device.objects.create(name='https://google.es', format='Dirección URL', user=admin)
        device_id = Device.objects.get(name='https://google.es').id
        response = self.client.post('/detection/detect/{}/'.format(device_id), follow=True)
        self.assertEquals(response.status_code, 403)
        self.assertEquals(response.content.decode('utf-8'), 'ERROR 403: No puedes detectar dispositivos de otros usuarios')
    

    def test_should_see_report_from_detection(self):
        device_id = Device.objects.get(name='127.0.0.1').id
        self.client.post('/detection/detect/{}/'.format(device_id), follow=True)
        response = self.client.get('/detection/results/{}/'.format(device_id), follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertTrue('127.0.0.1' in response.content.decode('utf-8'))