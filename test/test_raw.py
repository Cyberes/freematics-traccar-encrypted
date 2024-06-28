import socket
import binascii

from Crypto.Cipher import ChaCha20_Poly1305

# Send an initalization message and decrypt the response.
# Use this key: d38a3b96a26d0b1139bd30c174884f5dbc8eaaf492493725633ecebfa4ab19e9

# The server's address and port
server_address = ('localhost', 5171)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Convert hex string to bytes
ciphertext = binascii.unhexlify('40a7a1ef284e36e65cdb87abdb9aaea7ba4df5ae527b7311ba79a7d7f73729268d5b136c0c701fe366d775315f33e9ef893214fbf26a6ec281c8eadf46663b9d90')

# Send the encrypted message to the server
sock.sendto(ciphertext, server_address)

# Receive the response from the server
response, server = sock.recvfrom(4096)

# Decrypt that response
key = bytes.fromhex('d38a3b96a26d0b1139bd30c174884f5dbc8eaaf492493725633ecebfa4ab19e9')
# ChaCha20_Poly1305 nonce size is 12 bytes and tag size is 16 bytes
nonce = response[:12]
ciphertext_and_tag = response[12:]
ciphertext = ciphertext_and_tag[:-16]
tag = ciphertext_and_tag[-16:]

cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)

print("Decrypted message: ", plaintext)

sock.close()
