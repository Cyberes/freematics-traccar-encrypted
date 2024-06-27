import socket
import time

from Crypto.Cipher import ChaCha20_Poly1305

# The server's address and port
server_address = ('localhost', 5171)

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# The message to be sent
message = ('Hello, Server! ' + str(time.time())).encode()

# The key and nonce
key = bytes.fromhex('example123')

# Encrypt the message
cipher = ChaCha20_Poly1305.new(key=key)
ciphertext, tag = cipher.encrypt_and_digest(message)

# Send the encrypted message to the server
sock.sendto(cipher.nonce + ciphertext + tag, server_address)
sock.close()

cipher = ChaCha20_Poly1305.new(key=key, nonce=cipher.nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext)
