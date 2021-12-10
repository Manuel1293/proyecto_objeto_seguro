from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


class ObjetoSeguro:
    def __init__(self,nombre):
        self.nombre= nombre

    #genera la llave privada y su correspondiente llave publica
    def gen_llave(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open("receiver.pem", "wb")
        file_out.write(public_key)
        file_out.close()

    def saludar(self, name, msj):
        pass

    def responder(self,msj):
        pass

    def llave_publica(self):
        pass
    def cifrar_msj(self,pub_key,msj):
        msj = "hola mundo".encode("utf-8")
        file_out = open("msj_cifrado.bin", "wb")

        recipient_key = RSA.import_key(open("receiver.pem").read())
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        #se cifra el archivo on la llave de sesion AES
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(msj)
        [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
        file_out.close()
        return file_out

    def descifrar_msj(self, msj):
        file_in = open("msj_cifrado.bin", "rb")

        private_key = RSA.import_key(open("private.pem").read())

        enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        msj = cipher_aes.decrypt_and_verify(ciphertext, tag)
        #print(data.decode("utf-8")) OJO ME FALTA CONVERTIRLO A BASE64
        return msj.decode("utf-8")

    def codificar64(self,msj):
        pass
    def decodificar64(self, msj):
        pass
    def almacenar_msj(self,msj):
        pass
    def consultar_msj(self,id):
        pass
    def esperar_respuesta(self, msj):
        pass

