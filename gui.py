import tkinter as tk 
from tkinter import filedialog, messagebox  # Окна выбора файлов и всплывающие сообщения
from newkey import DigitalSignature  #для работы с цифровыми подписями

class DigitalSignatureApp:
    def __init__(self, root):
        # Создаём главное окно программы
        self.root = root
        self.root.title("Цифровая подпись файлов")
        self.root.geometry("800x600") 
        
        # Создаём объект для работы с подписями
        self.digital_signature = DigitalSignature()
        
        # Кнопка для создания сертификата
        self.generate_cert_btn = tk.Button(root, text="Создать сертификат", command=self.generate_certificate)
        self.generate_cert_btn.place(x=50, y=50)
        
        # Кнопка для подписания файла
        self.sign_btn = tk.Button(root, text="Подписать файл", command=self.sign_file)
        self.sign_btn.place(x=300, y=300)
        
        # Кнопка для проверки подписи
        self.verify_btn = tk.Button(root, text="Проверить подпись", command=self.verify_signature)
        self.verify_btn.place(x=300, y=400)
        
        # Поля для ввода данных при создании сертификата (страна, город, имя)
        self.country_label = tk.Label(root, text="Страна:")
        self.country_label.place(x=50, y=150)
        self.country_entry = tk.Entry(root)
        self.country_entry.insert(0, "uz")
        self.country_entry.place(x=200, y=150)

        self.city_label = tk.Label(root, text="Город:")
        self.city_label.place(x=50, y=200)
        self.city_entry = tk.Entry(root)
        self.city_entry.insert(0, "")
        self.city_entry.place(x=200, y=200)

        self.name_label = tk.Label(root, text="Имя:")
        self.name_label.place(x=50, y=250)
        self.name_entry = tk.Entry(root)
        self.name_entry.insert(0, "")
        self.name_entry.place(x=200, y=250)
    
    def generate_certificate(self):
        # Создание сертификата с введёнными пользователем данными
        country = self.country_entry.get()  
        city = self.city_entry.get()
        name = self.name_entry.get() 
        
        self.digital_signature.generate_keys_and_cert(country, city, name)  # Генерация ключей и сертификата
        messagebox.showinfo("Успех", "Ключи и сертификат созданы!")
    
    def sign_file(self):
        # Подписание выбранного файла
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        signature_path = self.digital_signature.sign_file(file_path)  # Создание цифровой подписи
        messagebox.showinfo("Успех", f"Файл подписан! Подпись сохранена в {signature_path}")
    
    def verify_signature(self):
        # Проверка подписи файла
        file_path = filedialog.askopenfilename(title="Выберите файл для проверки")
        if not file_path:
            return
        signature_path = filedialog.askopenfilename(title="Выберите подпись файла")
        if not signature_path:
            return
        
        cert_info, valid = self.digital_signature.verify_signature(file_path, signature_path)  # Проверяем подпись
        if valid:
            messagebox.showinfo("Результат", f" Подпись верна!\n\n{cert_info}")
        else:
            messagebox.showerror("Результат", " Подпись неверна!")

if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)  # Запуск приложения
    root.mainloop()  # Отображение окна
