import secrets
import string
import unittest

from project import db, app
from project.books.models import Book
from sqlalchemy.exc import IntegrityError


class BookModelTestCase(unittest.TestCase):

    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    # 1. TESTY POPRAWNYCH DANYCH

    def test_create_book_basic(self):
        book = Book(name='Python 101', author='Jan Kowalski', year_published=2020, book_type='5days')
        db.session.add(book)
        db.session.commit()
        self.assertIsNotNone(book.id)

    def test_default_status_is_available(self):
        book = Book(name='Hobbit', author='Tolkien', year_published=1937, book_type='5days')
        db.session.add(book)
        db.session.commit()
        self.assertEqual(book.status, 'available')

    def test_book_fields_stored_correctly(self):
        book = Book(name='1984', author='George Orwell', year_published=1949, book_type='10days')
        db.session.add(book)
        db.session.commit()
        fetched = db.session.get(Book, book.id)
        self.assertEqual(fetched.name, '1984')
        self.assertEqual(fetched.author, 'George Orwell')
        self.assertEqual(fetched.year_published, 1949)
        self.assertEqual(fetched.book_type, '10days')

    # 2. TESTY NIEPOPRAWNYCH DANYCH

    def test_duplicate_book_name_raises(self):
        db.session.add(Book(name='Duplikat', author='Autor 1', year_published=2000, book_type='2days'))
        db.session.commit()
        db.session.add(Book(name='Duplikat', author='Autor 2', year_published=2001, book_type='5days'))
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_year_published_negative(self):
        with self.assertRaises(ValueError):
            book = Book(name='AncientBook', author='Unknown', year_published=-500, book_type='2days')
        db.session.add(book)
        db.session.commit()
    
    def test_invalid_book_type(self):
        with self.assertRaises(ValueError):
            book = Book(name='InvalidTypeBook', author='Author', year_published=2020, book_type='INVALID')
        db.session.add(book)
        db.session.commit()

    # 3. TESTY WSTRZYKNIĘCIA SQL i JAVASCRIPT (XSS)

    def test_sql_injection_drop_table(self):
        payload = "'; DROP TABLE books; --"
        book = Book(name=payload, author='Hacker', year_published=2023, book_type='2days')
        db.session.add(book)
        db.session.commit()
        fetched = db.session.get(Book, book.id)
        self.assertEqual(fetched.name, payload)
        self.assertGreaterEqual(db.session.query(Book).count(), 1)

    def test_xss_script_tag_in_name(self):
        payload = "<script>alert('XSS')</script>"
        book = Book(name=payload, author='Author', year_published=2023, book_type='2days')
        db.session.add(book)
        db.session.commit()
        fetched = db.session.get(Book, book.id)
        self.assertEqual(fetched.name, payload)

    def test_xss_javascript_protocol_in_name(self):
        payload = "javascript:alert('xss')"
        book = Book(name=payload, author='Author', year_published=2023, book_type='10days')
        db.session.add(book)
        db.session.commit()
        fetched = db.session.get(Book, book.id)
        self.assertEqual(fetched.name, payload)

    # 4. TESTY EKSTREMALNE

    def test_name_exactly_64_characters(self):
        name = 'A' * 64
        book = Book(name=name, author='Author', year_published=2000, book_type='2days')
        db.session.add(book)
        db.session.commit()
        self.assertEqual(len(db.session.get(Book, book.id).name), 64)

    def test_unicode_name(self):
        """Unicode"""
        payload = 'Книга 本 '
        book = Book(name=payload, author='Author', year_published=2021, book_type='10days')
        db.session.add(book)
        db.session.commit()
        self.assertEqual(db.session.get(Book, book.id).name, payload)


if __name__ == '__main__':
    unittest.main()
