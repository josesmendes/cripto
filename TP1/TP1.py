import asyncio
from ascon import _ascon 

# Função para gerar chaves usando Ascon em modo XOF
def generate_keys(seed):
    key = _ascon.ascon_hash(seed, variant = "Ascon-Xof", hashlength=16)
    nonce = _ascon.ascon_hash(seed, variant="Ascon-Xof", hashlength=16)
#    key_gen.absorb(seed)
#    key = key_gen.squeeze(32)  # 32-byte key for encryption/authentication
#    nonce = key_gen.squeeze(16)  # 16-byte nonce
    return key, nonce

# Função para criptografar e autenticar dados
def encrypt_and_authenticate(key, nonce, data, associated_data=b''):
    cipher = _ascon.ascon_encrypt(key, nonce=nonce,associateddata=associated_data, plaintext=data, variant="Ascon-128")
#    cipher_header = cipher.encrypt(nonce, associated_data)
#   cipher_text = cipher.encrypt(nonce, data)
    return cipher

# Função para descriptografar e verificar a autenticação dos dados
def decrypt_and_verify(key, nonce, cipher_text, associated_data=b''):
    plain_txt = _ascon.ascon_decrypt(key, nonce=nonce,associateddata=associated_data, ciphertext=cipher_text, variant="Ascon-128")
    return plain_txt


# def main():
#     print("hello_world")
#     key, nonce = generate_keys(b"cripto")
#     cifra = encrypt_and_authenticate(key,nonce,b"cripto2024")
#     print(cifra)
#     print(decrypt_and_verify(key,nonce,cifra))

async def emitter():
    # Emitter's keys
    emitter_key, emitter_nonce = generate_keys(b"emitter_seed")

    # Message to be sent
    message = b"Hello, Receiver!"

    # Encrypt and authenticate the message
    encrypted_message = encrypt_and_authenticate(emitter_key, emitter_nonce, message)

    # Establish connection with the Receiver
    reader, writer = await asyncio.open_connection('localhost', 8888)

    # Send the encrypted message
    writer.write(encrypted_message)
    await writer.drain()

    # Close the connection
    writer.close()

# Receiver
async def receiver(reader, writer):
    # Receiver's keys
    receiver_key, receiver_nonce = generate_keys(b"receiver_seed")

    # Receive the encrypted message
    data = await reader.read()

    # Decrypt and verify the message
    decrypted_data = decrypt_and_verify(receiver_key, receiver_nonce, data)
    print(f"Received and decrypted data: {decrypted_data}")

# Main function to start the server and run the emitter
async def main():
    server = await asyncio.start_server(receiver, 'localhost', 8888)

    # Run the emitter concurrently with the server
    await asyncio.gather(server.serve_forever(), emitter())

if __name__ == "__main__":
    asyncio.run(main())
    
# class Receiver:
#     async def receive_action(self, queue):
#         while True:
#             action = await queue.get()
#             print("Received action:", action)

# class Emitter:
#     async def emit_actions(self, queue):
#         actions = ["action1", "action2", "action3"]
#         for action in actions:
#             await asyncio.sleep(1)  # Simulating some asynchronous action
#             await queue.put(action)
#             print("Emitted action:", action)

# async def main():
#     queue = asyncio.Queue()
#     receiver = Receiver()
#     emitter = Emitter()

#     receiver_task = asyncio.create_task(receiver.receive_action(queue))
#     emitter_task = asyncio.create_task(emitter.emit_actions(queue))

#     await asyncio.gather(receiver_task, emitter_task)

# if __name__ == "__main__":
#     asyncio.run(main())
    