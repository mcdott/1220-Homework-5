import os
from unittest import TestCase
from datetime import date
from bs4 import BeautifulSoup
 
from books_app.extensions import app, db, bcrypt
from books_app.models import Book, Author, User, Audience

"""
Run these tests with the command:
python -m unittest books_app.main.tests
"""

#################################################
# Setup
#################################################

def create_books():
    a1 = Author(name='Harper Lee')
    b1 = Book(
        title='To Kill a Mockingbird',
        publish_date=date(1960, 7, 11),
        author=a1
    )
    db.session.add(b1)

    a2 = Author(name='Sylvia Plath')
    b2 = Book(title='The Bell Jar', author=a2)
    db.session.add(b2)
    db.session.commit()

def create_user():
    password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='me1', password=password_hash)
    db.session.add(user)
    db.session.commit()

#################################################
# Tests
#################################################

class AuthTests(TestCase):
    """Tests for authentication (login & signup)."""
 
    def setUp(self):
        """Executed prior to each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.drop_all()
        db.create_all()


    def test_signup(self):
        """Test that a user can sign up."""
        # - Make a POST request to /signup, sending a username & password
        response = self.app.post('/signup', data={'username': 'test_user', 'password': 'test_password'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'http://localhost/login')

        # - Check that the user now exists in the database
        user = User.query.filter_by(username='test_user').first()
        self.assertIsNotNone(user)
        self.assertTrue(bcrypt.check_password_hash(user.password, 'test_password'))

    def test_signup_existing_user(self):
        """Test that a user cannot sign up with an existing username."""
        # Create a user
        create_user()

        # Make a POST request to /signup, sending the same username & password
        response = self.app.post('/signup', data=dict(
            username='me1',
            password='password'
        ), follow_redirects=True)

        # Check that the error message is displayed
        self.assertIn(b'That username is taken. Please choose a different one.', response.data)


    def test_login_correct_password(self):
        """Test that a user can log in with the correct password."""
        # - Create a user
        create_user()

        # - Make a POST request to /login, sending the created username & password
        response = self.app.post('/login', data=dict(
            username='me1', 
            password='password'
        ), follow_redirects=True)

        # - Check that the "login" button is not displayed on the homepage
        self.assertNotIn(b'Login', response.data)
       

    def test_login_nonexistent_user(self):
        """Test that a user cannot log in with a nonexistent username."""
        # - Make a POST request to /login, sending a username & password
        response = self.app.post('/login', data=dict(
            username='nonexistent_user', 
            password='password'
        ), follow_redirects=True)
        # - Check that the login form is displayed again, with error message
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'No user with that username. Please try again.', response.data)

    # def test_login_incorrect_password(self):
    #     """Test that a user cannot log in with an incorrect password."""
    #     # Create a user
    #     create_user()
    #     # - Make a POST request to /login, sending the created username &
    #     #   an incorrect password
    #     response = self.app.post('/login', data=dict(
    #         username='me1', 
    #         password='incorrect_password'
    #     ), follow_redirects=True)
    #     # - Check that the login form is displayed again, with error message
    #     self.assertIn(b'Password doesn\'t match. Please try again.', response.data)

    def test_login_incorrect_password(self):
        """Test that a user cannot log in with an incorrect password."""
        # Create a user
        create_user()

        # Make a POST request to /login, sending the created username & an incorrect password
        response = self.app.post('/login', data=dict(
            username='me1', 
            password='incorrect_password'
        ), follow_redirects=True)

        # Check that the login form is displayed again, with error message
        soup = BeautifulSoup(response.data, 'html.parser')
        error_li = soup.select_one('.error')
        self.assertEqual(error_li.text, "Password doesn't match. Please try again.")


    def test_logout(self):
        """Test that a user can log out."""
        # - Create a user
        create_user()
        # - Log the user in (make a POST request to /login)
        response = self.app.post('/login', data=dict(
            username='me1', 
            password='password'
        ), follow_redirects=True)

        # - Make a GET request to /logout
        response = self.app.get('/logout')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'http://localhost/')
        response = self.app.get('/')

        # Note: the login button isn't part of the response data, so test for the logout button instead
        # # - Check that the "login" button appears on the homepage
        # self.assertIn(b'Login', response.data)

        # - Check that the "Log Out" button is absent on the homepage
        self.assertNotIn(b'Log Out', response.data)
