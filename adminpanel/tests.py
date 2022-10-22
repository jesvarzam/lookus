from django.test import TestCase
from django.contrib.auth.models import User

class AdminPanelTestCase(TestCase):

    def setUp(self):
        User.objects.create_user(username='admin', password='admin123$!')
        admin = User.objects.get(username='admin')
        admin.is_staff = True
        admin.save()

    
    def tearDown(self):
        return super().tearDown()

    
    def test_admin_should_login_and_access_admin_panel(self):
        response = self.client.post('/authentication/sign_in/', {'username': 'admin', 'password': 'admin123$!'}, follow=True)
        self.assertEquals(response.wsgi_request.path, '/')
        response = self.client.get('/admin', follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/admin/')
    

    def test_different_user_should_login_but_not_access_admin_panel(self):
        User.objects.create_user(username='testinguser', password='testinguser123')
        response = self.client.post('/authentication/sign_in/', {'username': 'testinguser', 'password': 'testinguser123'}, follow=True)
        self.assertEquals(response.wsgi_request.path, '/')
        response = self.client.get('/admin/')
        self.assertEquals(response.status_code, 403)

    
    def test_admin_should_see_registered_user_details(self):
        User.objects.create_user(username='testinguser', password='testinguser123')
        registered_user_id = User.objects.get(username='testinguser').id

        response = self.client.post('/authentication/sign_in/', {'username': 'admin', 'password': 'admin123$!'}, follow=True)
        response = self.client.get('/admin/users/{}'.format(str(registered_user_id)), follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.wsgi_request.path, '/admin/users/{}'.format(str(registered_user_id)))
        self.assertTrue('testinguser' in response.content.decode('utf-8'))
    

    def test_admin_should_not_see_unexistent_user_details(self):
        response = self.client.post('/authentication/sign_in/', {'username': 'admin', 'password': 'admin123$!'}, follow=True)
        response = self.client.get('/admin/users/5', follow=True)
        self.assertEquals(response.status_code, 404)
        self.assertTrue('No existe ningún usuario con ese id', response.content.decode('utf-8'))
    
    
    def test_admin_should_remove_user(self):
        User.objects.create_user(username='testinguser', password='testinguser123')
        registered_user_id = User.objects.get(username='testinguser').id

        response = self.client.post('/authentication/sign_in/', {'username': 'admin', 'password': 'admin123$!'}, follow=True)
        response = self.client.get('/admin/users/remove/{}'.format(str(registered_user_id)), follow=True)
        self.assertEquals(response.status_code, 200)
        self.assertTrue('Usuario eliminado con éxito' in response.content.decode('utf-8'))
        self.assertTrue('Aún no hay ningún usuario registrado' in response.content.decode('utf-8'))
        self.assertEquals(User.objects.all().exclude(username='admin').count(), 0)