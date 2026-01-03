import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Replica la funzione Md() di JavaScript.
    Usa PBKDF2-HMAC-SHA256 per derivare la chiave di cifratura.
    """
    # La password deve essere in bytes
    password_bytes = password.encode('utf-8')

    # 100,000 iterazioni, SHA-256, per una chiave da 256 bit (32 bytes)
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        100000,
        dklen=32  # 256 bits
    )
    return kdf

def decrypt_data(encrypted_b64: str, password: str) -> str:
    """
    Replica la funzione Id() di JavaScript.
    Decifra il contenuto usando la chiave derivata.
    """
    # 1. Decodifica da Base64 e estrai le parti
    encrypted_data = base64.b64decode(encrypted_b64)

    salt = encrypted_data[0:16]
    iv = encrypted_data[16:28]      # "nonce"
    auth_tag = encrypted_data[28:44]
    ciphertext = encrypted_data[44:]

    # 2. Combina ciphertext e auth tag, come fa la Web Crypto API
    ciphertext_with_tag = ciphertext + auth_tag

    # 3. Deriva la chiave di decifratura
    key = derive_key(password, salt)

    # 4. Decifra usando AES-GCM
    aesgcm = AESGCM(key)
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)

    return decrypted_bytes.decode('utf-8')

# --- Script Principale ---
if __name__ == "__main__":
    encrypted_content = "hlRAqw3zFxnrgUw1GZusk+whhQHE0F+g7YjWjoJvpZRSCoDzehjXsEX1wQ6TTlOPyEJ/k+AEiMOxdqywh/86AOmhTaXNyZAvbHUVjfMdTqdzxmLXZJwI5ynI"

    password_candidates = [
        "THM{There.is.no.EASTmas.without.Hopper}", # Prova 1: La flag esatta
        "There.is.no.EASTmas.without.Hopper",    # Prova 2: Senza le parentesi graffe
        "There is no EASTmas without Hopper"     # Prova 3: Con gli spazi
    ]

    print("Inizio tentativo di decifratura...")

    for password in password_candidates:
        print(f"[*] Provo con la chiave: \"{password}\"")
        try:
            decrypted_message = decrypt_data(encrypted_content, password)
            print("\n[+] SUCCESSO! Messaggio segreto trovato:")
            print(f"    {decrypted_message}\n")
            break # Ferma il loop al primo successo
        except Exception as e:
            # L'eccezione più comune sarà InvalidTag se la chiave è sbagliata
            print(f"    -> Fallito: la chiave non è corretta (Errore: {type(e).__name__}).")
    else:
        print("\n[!] Nessuna delle chiavi provate ha funzionato.")
