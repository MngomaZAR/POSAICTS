import os
from dotenv import load_dotenv
import sqlite3
import bcrypt
import logging
import qrcode
import cv2
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from twilio.rest import Client
from kivy.clock import Clock

load_dotenv()  # Load environment variables from .env file

# Configure logging
logging.basicConfig(filename='pos_app.log', level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

DB_NAME = 'kivy_pos_system.db'

# Twilio configuration
ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')

# Database utilities
def create_db():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL,
            role TEXT NOT NULL,
            hours_worked REAL DEFAULT 0,
            sales_count INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);

        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_categories_name ON categories (name);

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category_id INTEGER NOT NULL,
            price REAL NOT NULL,
            quantity INTEGER NOT NULL,
            description TEXT,
            qr_code BLOB,
            FOREIGN KEY (category_id) REFERENCES categories(id)
        );

        CREATE INDEX IF NOT EXISTS idx_products_name ON products (name);
        CREATE INDEX IF NOT EXISTS idx_products_category_id ON products (category_id);

        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            qr_code BLOB
        );

        CREATE INDEX IF NOT EXISTS idx_customers_name ON customers (name);

        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total REAL NOT NULL,
            tax REAL NOT NULL,
            amount_paid REAL NOT NULL,
            change_given REAL NOT NULL,
            customer_id INTEGER,
            user_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_sales_timestamp ON sales (timestamp);

        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            FOREIGN KEY (sale_id) REFERENCES sales(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
        ''')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"Error creating database: {e}")

create_db()

# QR Code utilities
def generate_qr_code(data, directory='qr_codes'):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    if not os.path.exists(directory):
        os.makedirs(directory)
    img_path = f'{directory}/{data}.png'
    img.save(img_path)
    return img_path

def scan_qr_code():
    cap = cv2.VideoCapture(0)
    detector = cv2.QRCodeDetector()
    def capture_frame():
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            data, bbox, _ = detector.detectAndDecode(frame)
            if data:
                cap.release()
                cv2.destroyAllWindows()
                return data
            cv2.imshow("QR Code Scanner", frame)
            if cv2.waitKey(1) == ord("q"):
                break
        cap.release()
        cv2.destroyAllWindows()
    thread = threading.Thread(target=capture_frame)
    thread.start()
    thread.join()
    return None

# Authentication utilities
def authenticate_user(username, password):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, role FROM users WHERE username = ?", (username,))
        record = cursor.fetchone()
        conn.close()
        if record and bcrypt.checkpw(password.encode(), record[1]):
            return True, record[0], record[2]
    except sqlite3.Error as e:
        logging.error(f"Error authenticating user: {e}")
    return False, None, None

def update_sales_count(user_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET sales_count = sales_count + 1 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"Error updating sales count: {e}")

def update_hours_worked(user_id, hours):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET hours_worked = hours_worked + ? WHERE id = ?", (hours, user_id))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"Error updating hours worked: {e}")

def send_sms(phone_number, message):
    try:
        client = Client(ACCOUNT_SID, AUTH_TOKEN)
        message = client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        logging.info(f"SMS sent to {phone_number}: {message.sid}")
    except Exception as e:
        logging.error(f"Error sending SMS: {e}")

class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.username_input = TextInput(hint_text='Username', multiline=False, size_hint_y=None, height=40)
        self.password_input = TextInput(hint_text='Password', password=True, multiline=False, size_hint_y=None, height=40)
        login_button = Button(text='Login', size_hint_y=None, height=50, on_release=self.login)
        register_button = Button(text='Register', size_hint_y=None, height=50, on_release=self.go_to_register)

        layout.add_widget(Label(text='POS System', font_size='24sp', bold=True, size_hint_y=None, height=50))
        layout.add_widget(self.username_input)
        layout.add_widget(self.password_input)
        layout.add_widget(login_button)
        layout.add_widget(register_button)
        self.add_widget(layout)

    def login(self, instance):
        username = self.username_input.text
        password = self.password_input.text
        authenticated, user_id, role = authenticate_user(username, password)
        if authenticated:
            self.manager.current = 'dashboard'
            self.manager.get_screen('dashboard').user_id = user_id
            self.manager.get_screen('dashboard').role = role
        else:
            self.show_popup('Login Error', 'Invalid username or password.')

    def go_to_register(self, instance):
        self.manager.current = 'register'

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(None, None), size=(400, 200))
        popup.open()

class RegisterScreen(Screen):
    def __init__(self, **kwargs):
        super(RegisterScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.username_input = TextInput(hint_text='Username', multiline=False)
        self.password_input = TextInput(hint_text='Password', password=True, multiline=False)
        self.confirm_password_input = TextInput(hint_text='Confirm Password', password=True, multiline=False)
        self.role_input = TextInput(hint_text='Role (admin/POS Operator)', multiline=False)
        register_button = Button(text='Register', on_release=self.register)
        back_button = Button(text='Back to Login', on_release=self.go_to_login)

        layout.add_widget(Label(text='Register', font_size='24sp', bold=True, size_hint_y=None, height=50))
        layout.add_widget(self.username_input)
        layout.add_widget(self.password_input)
        layout.add_widget(self.confirm_password_input)
        layout.add_widget(self.role_input)
        layout.add_widget(register_button)
        layout.add_widget(back_button)
        self.add_widget(layout)

    def register(self, instance):
        username = self.username_input.text
        password = self.password_input.text
        confirm_password = self.confirm_password_input.text
        role = self.role_input.text.lower()

        if password != confirm_password:
            self.show_popup("Registration Error", "Passwords do not match.")
            return

        if role not in ['admin', 'pos operator']:
            self.show_popup("Registration Error", "Role must be 'admin' or 'POS Operator'.")
            return

        if len(username) == 0 or len(password) == 0:
            self.show_popup("Registration Error", "Username and Password cannot be empty.")
            return

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
            conn.commit()
            self.show_popup("Success", "Registration successful.")
            self.manager.current = 'login'
        except sqlite3.IntegrityError:
            self.show_popup("Registration Error", "Username already exists.")
        finally:
            conn.close()

    def go_to_login(self, instance):
        self.manager.current = 'login'

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(None, None), size=(400, 200))
        popup.open()

class DashboardScreen(Screen):
    def __init__(self, **kwargs):
        super(DashboardScreen, self).__init__(**kwargs)
        self.role = None
        self.user_id = None
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        layout.add_widget(Label(text='Dashboard', font_size='24sp', bold=True, size_hint_y=None, height=50))
        self.categories_button = Button(text='Manage Categories', on_release=self.go_to_categories)
        self.products_button = Button(text='Manage Products', on_release=self.go_to_products)
        self.pos_button = Button(text='POS', on_release=self.go_to_pos)
        self.sales_button = Button(text='Sales Report', on_release=self.go_to_sales)
        self.customers_button = Button(text='Customer Management', on_release=self.go_to_customers)
        self.logout_button = Button(text='Logout', on_release=self.logout)
        layout.add_widget(self.categories_button)
        layout.add_widget(self.products_button)
        layout.add_widget(self.pos_button)
        layout.add_widget(self.sales_button)
        layout.add_widget(self.customers_button)
        layout.add_widget(self.logout_button)
        self.add_widget(layout)

    def on_enter(self, *args):
        self.update_buttons_visibility()

    def update_buttons_visibility(self):
        if self.role == 'admin':
            self.categories_button.disabled = False
            self.products_button.disabled = False
            self.sales_button.disabled = False
        elif self.role == 'pos operator':
            self.categories_button.disabled = True
            self.products_button.disabled = True
            self.sales_button.disabled = True

    def go_to_categories(self, instance):
        self.manager.current = 'categories'

    def go_to_products(self, instance):
        self.manager.current = 'products'

    def go_to_pos(self, instance):
        self.manager.current = 'pos'

    def go_to_sales(self, instance):
        self.manager.current = 'sales'

    def go_to_customers(self, instance):
        self.manager.current = 'customers'

    def logout(self, instance):
        self.manager.current = 'login'

class CategoriesScreen(Screen):
    def __init__(self, **kwargs):
        super(CategoriesScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.name_input = TextInput(hint_text='Category Name', multiline=False)
        add_category_button = Button(text='Add Category', on_release=self.add_category)
        back_button = Button(text='Back to Dashboard', on_release=self.go_to_dashboard)

        layout.add_widget(Label(text='Manage Categories', font_size='24sp', bold=True, size_hint_y=None, height=50))
        layout.add_widget(self.name_input)
        layout.add_widget(add_category_button)
        layout.add_widget(back_button)
        self.add_widget(layout)

    def add_category(self, instance):
        name = self.name_input.text
        if not name:
            self.show_popup("Input Error", "Category name cannot be empty.")
            return

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO categories (name) VALUES (?)", (name,))
            conn.commit()
            self.show_popup("Success", "Category added successfully.")
        except sqlite3.Error as e:
            self.show_popup("Error", f"An error occurred: {e}")
        finally:
            conn.close()

    def go_to_dashboard(self, instance):
        self.manager.current = 'dashboard'

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(None, None), size=(400, 200))
        popup.open()

class ProductsScreen(Screen):
    def __init__(self, **kwargs):
        super(ProductsScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.name_input = TextInput(hint_text='Product Name', multiline=False)
        self.category_input = TextInput(hint_text='Category ID', multiline=False)
        self.price_input = TextInput(hint_text='Price', multiline=False)
        self.quantity_input = TextInput(hint_text='Quantity', multiline=False)
        self.description_input = TextInput(hint_text='Description', multiline=False)
        add_product_button = Button(text='Add Product', on_release=self.add_product)
        back_button = Button(text='Back to Dashboard', on_release=self.go_to_dashboard)

        layout.add_widget(Label(text='Manage Products', font_size='24sp', bold=True, size_hint_y=None, height=50))
        layout.add_widget(self.name_input)
        layout.add_widget(self.category_input)
        layout.add_widget(self.price_input)
        layout.add_widget(self.quantity_input)
        layout.add_widget(self.description_input)
        layout.add_widget(add_product_button)
        layout.add_widget(back_button)
        self.add_widget(layout)

    def add_product(self, instance):
        name = self.name_input.text
        category_id = self.category_input.text
        price = float(self.price_input.text)
        quantity = int(self.quantity_input.text)
        description = self.description_input.text

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO products (name, category_id, price, quantity, description) VALUES (?, ?, ?, ?, ?)",
                           (name, category_id, price, quantity, description))
            conn.commit()
            product_id = cursor.lastrowid
            qr_code_path = generate_qr_code(str(product_id))
            cursor.execute("UPDATE products SET qr_code = ? WHERE id = ?", (qr_code_path, product_id))
            conn.commit()
            self.show_popup("Success", "Product added successfully.")
        except sqlite3.Error as e:
            self.show_popup("Error", f"An error occurred: {e}")
        finally:
            conn.close()

    def go_to_dashboard(self, instance):
        self.manager.current = 'dashboard'

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(None, None), size=(400, 200))
        popup.open()

class POSScreen(Screen):
    def __init__(self, **kwargs):
        super(POSScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.product_search_input = TextInput(hint_text='Search Products', multiline=False)
        self.cart = []
        self.cart_label = Label(text='Cart is empty.')
        search_button = Button(text='Search', on_release=self.search_products)
        view_all_button = Button(text='View All Products', on_release=self.view_all_products)
        scan_button = Button(text='Scan Product QR', on_release=self.scan_product_qr)
        add_product_button = Button(text='Add Product', on_release=self.add_product_to_cart)
        self.grid_view = GridLayout(cols=2, spacing=10, size_hint_y=None)
        self.grid_view.bind(minimum_height=self.grid_view.setter('height'))
        self.scroll_view = ScrollView(size_hint=(1, None), size=(600, 400))
        self.scroll_view.add_widget(self.grid_view)
        checkout_button = Button(text='Checkout', on_release=self.proceed_to_checkout)
        back_button = Button(text='Back to Dashboard', on_release=self.go_to_dashboard)

        layout.add_widget(Label(text='POS', font_size='24sp', bold=True, size_hint_y=None, height=50))
        layout.add_widget(self.product_search_input)
        layout.add_widget(search_button)
        layout.add_widget(view_all_button)
        layout.add_widget(scan_button)
        layout.add_widget(self.scroll_view)
        layout.add_widget(self.cart_label)
        layout.add_widget(checkout_button)
        layout.add_widget(back_button)
        self.add_widget(layout)

    def search_products(self, instance):
        search_query = self.product_search_input.text
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, price, quantity FROM products WHERE name LIKE ? OR description LIKE ?",
                       ('%' + search_query + '%', '%' + search_query + '%'))
        products = cursor.fetchall()
        conn.close()
        self.show_products(products)

    def view_all_products(self, instance):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, price, quantity FROM products")
        products = cursor.fetchall()
        conn.close()
        self.show_products(products)

    def show_products(self, products):
        self.grid_view.clear_widgets()
        for product in products:
            box = BoxLayout(orientation='vertical', padding=10, spacing=10)
            box.add_widget(Label(text=f"{product[1]} - ${product[2]:.2f}"))
            box.add_widget(Label(text=f"Stock: {product[3]}"))
            box.add_widget(Button(text='Add to Cart', on_release=lambda btn, product=product: self.select_product(product)))
            self.grid_view.add_widget(box)

    def select_product(self, product):
        self.selected_product = product
        self.add_product_to_cart(None)

    def scan_product_qr(self, instance):
        qr_data = scan_qr_code()
        if qr_data:
            self.add_product_by_id(int(qr_data))

    def add_product_by_id(self, product_id):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, price, quantity FROM products WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        conn.close()
        if product:
            self.selected_product = product
            self.add_product_to_cart(None)
        else:
            self.show_popup("Error", "Product not found.")

    def add_product_to_cart(self, instance):
        if hasattr(self, 'selected_product'):
            self.cart.append(self.selected_product)
            self.update_cart_label()
        else:
            self.show_popup('Error', 'No product selected.')

    def update_cart_label(self):
        cart_text = '\n'.join([f"{product[1]} - ${product[2]:.2f}" for product in self.cart])
        self.cart_label.text = cart_text if cart_text else 'Cart is empty.'

    def proceed_to_checkout(self, instance):
        if not self.cart:
            self.show_popup('Error', 'Cart is empty.')
            return

        total_amount = sum([product[2] for product in self.cart])
        self.manager.current = 'checkout'
        self.manager.get_screen('checkout').update_total_amount(total_amount)

    def go_to_dashboard(self, instance):
        self.manager.current = 'dashboard'

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(None, None), size=(400, 200))
        popup.open()

class CheckoutScreen(Screen):
    def __init__(self, **kwargs):
        super(CheckoutScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.total_amount_label = Label(text='Total: $0.00')
        self.cash_input = TextInput(hint_text='Cash Given', multiline=False)
        self.change_label = Label(text='Change: $0.00')
        cash_payment_button = Button(text='Pay with Cash', on_release=self.process_cash_payment)
        card_payment_button = Button(text='Pay with Card', on_release=self.process_card_payment)
        scan_customer_button = Button(text='Scan Customer QR', on_release=self.scan_customer_qr)
        self.customer_id = None
        back_button = Button(text='Back to POS', on_release=self.go_to_pos)

        layout.add_widget(self.total_amount_label)
        layout.add_widget(self.cash_input)
        layout.add_widget(self.change_label)
        layout.add_widget(cash_payment_button)
        layout.add_widget(card_payment_button)
        layout.add_widget(scan_customer_button)
        layout.add_widget(back_button)
        self.add_widget(layout)

    def update_total_amount(self, amount):
        self.total_amount = amount
        self.total_amount_label.text = f'Total: ${amount:.2f}'

    def scan_customer_qr(self, instance):
        qr_data = scan_qr_code()
        if qr_data:
            self.customer_id = int(qr_data)

    def process_cash_payment(self, instance):
        try:
            cash_given = float(self.cash_input.text)
            if cash_given < self.total_amount:
                self.show_popup('Error', 'Insufficient cash given.')
            else:
                change = cash_given - self.total_amount
                self.change_label.text = f'Change: ${change:.2f}'
                self.complete_sale('cash', cash_given, change)
        except ValueError:
            self.show_popup('Error', 'Invalid cash amount.')

    def process_card_payment(self, instance):
        # Implement card machine processing
        self.complete_sale('card', self.total_amount, 0)

    def complete_sale(self, payment_method, amount_paid, change_given):
        user_id = self.manager.get_screen('dashboard').user_id
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO sales (total, tax, amount_paid, change_given, customer_id, user_id) VALUES (?, ?, ?, ?, ?, ?)",
                       (self.total_amount, 0, amount_paid, change_given, self.customer_id, user_id))
        sale_id = cursor.lastrowid
        for product in self.manager.get_screen('pos').cart:
            cursor.execute("INSERT INTO sale_items (sale_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
                           (sale_id, product[0], 1, product[2]))
            cursor.execute("UPDATE products SET quantity = quantity - 1 WHERE id = ?", (product[0],))
        conn.commit()
        conn.close()
        update_sales_count(user_id)
        self.show_popup('Success', 'Sale completed successfully.')
        Clock.schedule_once(lambda dt: self.generate_receipt(sale_id), 0.5)
        self.manager.get_screen('pos').cart.clear()
        self.manager.get_screen('pos').update_cart_label()
        self.manager.current = 'pos'

    def generate_receipt(self, sale_id):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT total, amount_paid, change_given, timestamp FROM sales WHERE id = ?", (sale_id,))
        sale = cursor.fetchone()
        cursor.execute("SELECT p.name, s.quantity, s.price FROM sale_items s JOIN products p ON s.product_id = p.id WHERE s.sale_id = ?", (sale_id,))
        items = cursor.fetchall()
        conn.close()

        receipt_content = "Receipt\n"
        receipt_content += f"Sale ID: {sale_id}\n"
        receipt_content += f"Date: {sale[3]}\n\n"
        receipt_content += "Items:\n"
        for item in items:
            receipt_content += f"{item[0]} x {item[1]} @ ${item[2]:.2f}\n"
        receipt_content += f"\nTotal: ${sale[0]:.2f}\n"
        receipt_content += f"Paid: ${sale[1]:.2f}\n"
        receipt_content += f"Change: ${sale[2]:.2f}\n"

        receipt_path = f'receipts/sale_{sale_id}.txt'
        if not os.path.exists('receipts'):
            os.makedirs('receipts')
        with open(receipt_path, 'w') as receipt_file:
            receipt_file.write(receipt_content)
        self.show_popup('Receipt', f'Receipt saved to {receipt_path}')

        # Send receipt via SMS if customer phone is available
        if self.customer_id:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT phone FROM customers WHERE id = ?", (self.customer_id,))
            customer_phone = cursor.fetchone()
            conn.close()
            if customer_phone:
                send_sms(customer_phone[0], receipt_content)

    def go_to_pos(self, instance):
        self.manager.current = 'pos'

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(None, None), size=(400, 200))
        popup.open()

class SalesScreen(Screen):
    def __init__(self, **kwargs):
        super(SalesScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.sales_label = Label(text='Sales Report')
        back_button = Button(text='Back to Dashboard', on_release=self.go_to_dashboard)

        layout.add_widget(Label(text='Sales Report', font_size='24sp', bold=True, size_hint_y=None, height=50))
        layout.add_widget(self.sales_label)
        layout.add_widget(back_button)
        self.add_widget(layout)

    def on_enter(self):
        self.update_sales_report()

    def update_sales_report(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, total, amount_paid, change_given, timestamp FROM sales")
        sales = cursor.fetchall()
        report = "Sales Report\n\n"
        for sale in sales:
            report += f"Sale ID: {sale[0]}, Total: ${sale[1]:.2f}, Paid: ${sale[2]:.2f}, Change: ${sale[3]:.2f}, Date: {sale[4]}\n"
        self.sales_label.text = report
        conn.close()

    def go_to_dashboard(self, instance):
        self.manager.current = 'dashboard'

class CustomerScreen(Screen):
    def __init__(self, **kwargs):
        super(CustomerScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        self.name_input = TextInput(hint_text='Customer Name', multiline=False)
        self.email_input = TextInput(hint_text='Customer Email', multiline=False)
        self.phone_input = TextInput(hint_text='Customer Phone', multiline=False)
        scan_button = Button(text='Scan Customer QR', on_release=self.scan_customer_qr)
        add_customer_button = Button(text='Add Customer', on_release=self.add_customer)
        back_button = Button(text='Back to Dashboard', on_release=self.go_to_dashboard)

        layout.add_widget(Label(text='Manage Customers', font_size='24sp', bold=True, size_hint_y=None, height=50))
        layout.add_widget(self.name_input)
        layout.add_widget(self.email_input)
        layout.add_widget(self.phone_input)
        layout.add_widget(scan_button)
        layout.add_widget(add_customer_button)
        layout.add_widget(back_button)
        self.add_widget(layout)

    def scan_customer_qr(self, instance):
        qr_data = scan_qr_code()
        if qr_data:
            self.customer_id = int(qr_data)
            self.load_customer(self.customer_id)

    def load_customer(self, customer_id):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT name, email, phone FROM customers WHERE id = ?", (customer_id,))
        customer = cursor.fetchone()
        conn.close()
        if customer:
            self.name_input.text = customer[0]
            self.email_input.text = customer[1]
            self.phone_input.text = customer[2]
        else:
            self.show_popup("Error", "Customer not found.")

    def add_customer(self, instance):
        name = self.name_input.text
        email = self.email_input.text
        phone = self.phone_input.text

        if not name or not email or not phone:
            self.show_popup("Input Error", "All fields are required.")
            return

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO customers (name, email, phone) VALUES (?, ?, ?)", (name, email, phone))
            conn.commit()
            customer_id = cursor.lastrowid
            qr_code_path = generate_qr_code(f"customer_{customer_id}", directory='customer_qr_codes')
            cursor.execute("UPDATE customers SET qr_code = ? WHERE id = ?", (qr_code_path, customer_id))
            conn.commit()
            self.show_popup("Success", "Customer added successfully.")
        except sqlite3.Error as e:
            self.show_popup("Error", f"An error occurred: {e}")
        finally:
            conn.close()

    def go_to_dashboard(self, instance):
        self.manager.current = 'dashboard'

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(None, None), size=(400, 200))
        popup.open()

class POSApp(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(RegisterScreen(name='register'))
        sm.add_widget(DashboardScreen(name='dashboard'))
        sm.add_widget(CategoriesScreen(name='categories'))
        sm.add_widget(ProductsScreen(name='products'))
        sm.add_widget(POSScreen(name='pos'))
        sm.add_widget(CheckoutScreen(name='checkout'))
        sm.add_widget(SalesScreen(name='sales'))
        sm.add_widget(CustomerScreen(name='customers'))
        return sm

if __name__ == '__main__':
    POSApp().run()
