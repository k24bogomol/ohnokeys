from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import CertificateBuilder, Name, NameAttribute, load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.x509 import random_serial_number
import datetime
from cryptography.exceptions import InvalidSignature

class DigitalSignature:
    def __init__(self):
        # Инициализация класса, создаём пустые переменные для ключей и сертификата
        self.private_key = None
        self.public_key = None
        self.cert = None

    def generate_keys_and_cert(self, country, city, name):
        """Генерация пары ключей (закрытый и открытый) и сертификата"""
        
        # Создаём закрытый ключ (private key)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Сохраняем закрытый ключ в файл
        with open("private.pem", "wb") as private_file:
            private_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Получаем открытый ключ (public key) из закрытого
        self.public_key = self.private_key.public_key()
        
        # Сохраняем открытый ключ в файл
        with open("public.pem", "wb") as public_file:
            public_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        # Создаём информацию о владельце сертификата
        subject = issuer = Name([
            NameAttribute(NameOID.COUNTRY_NAME, country),
            NameAttribute(NameOID.LOCALITY_NAME, city),
            NameAttribute(NameOID.COMMON_NAME, name),
        ])

        # Формируем сертификат, привязываем к нему открытый ключ и подписываем закрытым ключом
        self.cert = CertificateBuilder().subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(self.public_key) \
            .serial_number(random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
            .sign(self.private_key, hashes.SHA256(), default_backend())

        # Сохраняем сертификат в файл
        with open("certificate.pem", "wb") as cert_file:
            cert_file.write(self.cert.public_bytes(serialization.Encoding.PEM))

    def sign_file(self, file_path):
        """Создание цифровой подписи файла"""
        
        # Читаем содержимое файла
        with open(file_path, "rb") as f:
            data = f.read()

        # Подписываем содержимое файла с помощью закрытого ключа
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Сохраняем подпись в отдельный файл
        signature_path = file_path + ".sig"
        with open(signature_path, "wb") as sig_file:
            sig_file.write(signature)

        return signature_path

    def verify_signature(self, file_path, signature_path):
        """Проверка цифровой подписи"""
        
        # Читаем оригинальный файл
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Читаем файл с подписью
        with open(signature_path, "rb") as sig_file:
            signature = sig_file.read()

        # Загружаем сертификат из файла
        with open("certificate.pem", "rb") as cert_file:
            cert_data = cert_file.read()
        
        # Декодируем сертификат
        cert = load_pem_x509_certificate(cert_data, default_backend())

        # Получаем открытый ключ из сертификата
        public_key = cert.public_key()

        try:
            # Проверяем подпись с помощью открытого ключа
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Если проверка успешна, получаем информацию о сертификате
            cert_info = f"Сертификат:\nСтрана: {cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value}\nГород: {cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value}\nИмя: {cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}"
            return cert_info, True
        except InvalidSignature:
            # Если подпись не совпадает, возвращаем False
            return None, False
