import asyncio
import secrets
from ascon import _ascon 
import os
import random
from pickle import dumps, loads
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import x448, ed448
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey

import nest_asyncio

nest_asyncio.apply()


def generateKeys():
    # Generate private key for exchange
    private_key = x448.X448PrivateKey.generate()
    
    # Generate public key thorugh private key
    peer_public_key = private_key.public_key()
    
    return private_key, peer_public_key

def generateShared(private_key, peer_public_key):
    
    peer_cipher_key = x448.X448PublicKey.from_public_bytes(peer_public_key)
    
    # Gerar uma chave partilha para cifra
    shared_key = private_key.exchange(peer_cipher_key)
    
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16, #32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    
    return derived_key

def generateSignKeys():
    
    ## Chave privada para assinar
    private_key = Ed448PrivateKey.generate()
    
    ## Chave pública para autenticar
    public_key = private_key.public_key()
   
    return private_key, public_key
    
def signMsg(prv_key, msg):
    
    signature = prv_key.sign(msg)
    
    return signature

def init_agents():
    private_cipher_key, public_cipher_key = generateKeys()
    private_sign_key, public_sign_key = generateSignKeys()

    msg_to_sign = public_cipher_key.public_bytes(encoding=serialization.Encoding.Raw,
                                       format=serialization.PublicFormat.Raw
                                    )

    signed_message = signMsg(private_sign_key,msg_to_sign)
    content = {'cipher_key': public_cipher_key.public_bytes(encoding=serialization.Encoding.Raw,
                                       format=serialization.PublicFormat.Raw
                                    ), 
           'sign_key': public_sign_key.public_bytes(encoding=serialization.Encoding.Raw,
                                       format=serialization.PublicFormat.Raw
                                    ),
           'message': signed_message}
    return private_cipher_key, private_sign_key, content

async def send(queue, msg):
    
    await asyncio.sleep(random.random())
        
    # put the item in the queue
    await queue.put(msg)
    
    await asyncio.sleep(random.random())
    
async def receive(queue):
    item = await queue.get()

    await asyncio.sleep(random.random())
    aux = loads(item)

    return aux

def tweak_blocks_tpbc(nounce, counter, plaintext_blocks, key, auth, iv):
    cyphered_text = b""
    zero = b"\x00"
    
    for elem in (plaintext_blocks):        
        tweak = nounce + counter + zero
        
        cyphered_block = tpbc(tweak, key, elem, iv)
        cyphered_text += cyphered_block

        counter += 1

        aux = b""
        for x,y in zip(auth, elem):
            word = x ^ y
            aux += word.to_bytes(1, 'big')
        
        auth = aux
        
    return counter, auth, cyphered_text
    
def tpbc(tweak, key, block, iv):
    tweaked_key = tweak + key
    encryptor = Cipher(algorithms.AES256(tweaked_key), modes.CBC(iv)).encryptor()
    encrypt_block = encryptor.update(block) + encryptor.finalize()
    return encrypt_block

def padding(block, size):
    len_block = len(block)
    
    for _ in range (len_block, size): # Adds the value 0 until the size the last block is 0
        block += b"\x00"
    
    return block, len_block

def unpad(last_block, size_block):
    
    clean_text = last_block[:size_block]
    
    return clean_text

def un_tpbc(tweak, key, block, iv):
    tweaked_key = tweak + key
    cipher = Cipher(algorithms.AES256(tweaked_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plain_block = decryptor.update(block) + decryptor.finalize()
    return plain_block

def undo_tweakable_first_blocks(nounce, counter, block_ciphertext, key, auth, iv):
    plaintext = b""    
    for elem in (block_ciphertext[:-1]):        
        tweak = nounce + counter +  b"\x00"
        
        plain_block = un_tpbc(tweak, key, elem, iv)
        plaintext += plain_block
        
        counter +=1
        
        aux = b""
        for x,y in zip(auth, plain_block):
            word = x ^ y
            aux += word.to_bytes(1, 'big')
        
        auth = aux
        
    return counter, auth, plaintext

def enc_txt(key, plaintext):
    block_size = 16  # 16-byte blocks for AES256
    nounce_size = 8

    nounce_temp = hashes.Hash(hashes.SHA256()).finalize()
    nounce = nounce_temp[:nounce_size] # 8-byte array for the tweak nounce 

    initial_counter = os.urandom(nounce_size-1) # 8-byte array for the tweak counter
    counter = initial_counter
    iv = os.urandom(16) # initial value for CBC

    plaintext_blocks = divide_into_blocks(plaintext, block_size)#divide plaintext to fit the AES256 block size 

    last_block, last_block_size = padding(bytes(plaintext_blocks[-1], 'utf8'),block_size)#fill the remaining space in the last block

    auth = b"" 
    for _ in range (block_size): # create the authentication block
        auth += b"\x00"
    
    counter, auth, encrypt_text = tweak_blocks_tpbc(nounce, counter, plaintext_blocks[:-1], key, auth, iv) #encrypt the m-1 first blocks

    tweak = nounce + counter +  b"\x00" #create the tweak for the last block
    length_block = last_block_size.to_bytes(16, 'big') # Turns the length of the last block into a 16 bytes block
    encrypt_mask = tpbc(tweak, key, length_block, iv) # creates the chipher to XOR the last block
    
    encrypt_block = b""
    for x,y in zip(last_block, encrypt_mask): #XOR the last block to encrypt it
        word = x ^ y
        encrypt_block += word.to_bytes(1, 'big')

    encrypt_text += encrypt_block #concant the last block to the rest 

    aux = b""
    for x,y in zip(auth, last_block): #XOR the last block with the authentication block
        word = x ^ y
        aux += word.to_bytes(1, 'big')
    auth = aux
    
    #
    tweak = nounce + counter + b"\x01" # create authentication tag
    tag = tpbc(tweak, key, auth, iv)
    
    return {"encrypt_text": encrypt_text, "tag": tag, "nounce": nounce, "counter": initial_counter, "pad": last_block_size, "iv": iv}

def dec_txt(key, encrypt_blocks):
    encrypt_text = encrypt_blocks['encrypt_text'] # bytes
    tag_rcv = encrypt_blocks['tag']
    nounce = encrypt_blocks['nounce']
    counter = encrypt_blocks['counter']
    last_block_size = encrypt_blocks['pad']
    iv = encrypt_blocks['iv']
    
    block_size = 16
    
    block_ciphertext = divide_into_blocks(encrypt_text, block_size)  # list of block of bytes. Block size 16 bytes
    
    # i= 0 ... m - 1
    auth = b"" 
    for _ in range (block_size): # array of bytes with size 16 bytes
        auth += b"\x00"
    counter, auth, plaintext = undo_tweakable_first_blocks(nounce, counter, block_ciphertext, key, auth, iv)
        
    # i = m
    tweak = nounce + counter + b"\x00"
    length_block = last_block_size.to_bytes(16, 'big')
    c_aux = tpbc(tweak, key, length_block, iv)
    
    plain_block = b""
    for x,y in zip(block_ciphertext[-1], c_aux):
        word = x ^ y
        plain_block += word.to_bytes(1, 'big')
    
    plaintext += unpad(plain_block, block_size) # ct: bytes
    
    aux = b""
    for x,y in zip(auth, plain_block):
        word = x ^ y
        aux += word.to_bytes(1, 'big')
    auth = aux
    
    # Autenticação
    tweak = nounce + counter + b"\x01"
    
    tag = tpbc(tweak, key, auth, iv)
    
    tag_valid = True
    if tag != tag_rcv:
        tag_valid = False
        
    return plaintext, tag_valid

def generate_nonce(key, counter):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,  # Length of the nonce in bytes (128 bits)
        salt=counter.to_bytes(4, 'big'),  # Concatenate message_id and counter as salt
        iterations=10
    )
    nonce = kdf.derive(key)
    return nonce

def divide_into_blocks(text, block_size):
    blocks = []
    for i in range(0, len(text), block_size):
        block = text[i:i + block_size]
        blocks.append(block)
    return blocks


async def emitter(plaintext, queue):

    # Emitter's keys
    emitter_private_cipher_key, emitter_private_sign_key, content = init_agents()

    ## Enviar a chaves públicas para o peer
    print("[E] SENDING PUBLIC KEYS")
    await send(queue, dumps(content))
    
    ## Receber as chaves públicas do peer
    data = await receive(queue)

    print("[E] RECEIVED PEER PUBLIC KEYS")
    
    pub_peer_cipher = data['cipher_key']
    pub_peer_sign = data['sign_key']
    signature = data['message']
    # print("[E] Receiver pub_key_cipher: " +str(pub_peer_cipher))
    # print("[E] Receiver pub_key_sign: " +str(pub_peer_sign))
    # print("[E] Receiver signature: " +str(signature))
 
    try:
        ## Obter a chave pública (Assinatura)
        peer_sign_pubkey = ed448.Ed448PublicKey.from_public_bytes(pub_peer_sign)
        
        ## Verificar a assinatura da chave pública
        peer_sign_pubkey.verify(signature, pub_peer_cipher)
        print("[E] SIGNATURE VALIDATED")
        
        ## Criar as chaves partilhadas (cifrar/autenticar)
        cipher_shared = generateShared(emitter_private_cipher_key, pub_peer_cipher)

        print("[E] CIPHER SHARED: "+str(cipher_shared))

        ## Cifrar a mensagem
        pkg = enc_txt(cipher_shared, plaintext)
        print("[E] MESSAGE ENCRYPTED")

        ## Assinar e enviar a mensagem
        pkg_b = dumps(pkg)
        sig = signMsg(emitter_private_sign_key, pkg_b)

        ## a Enviar...
        msg_final = {'sig': sig, 'msg': dumps(pkg)}

        print("[E] SENDING MESSAGE")
        await send(queue, dumps(msg_final))

        print("[E] END")    
    except InvalidSignature:
        print("A assinatura não foi verificada com sucesso!")

# Receiver
async def receiver(queue):
    receiver_cipher, receiver_sign, content = init_agents()
    
    ## Receber as chaves publicas do peer
    pub_keys = await receive(queue)
    
    pub_peer_cipher = pub_keys['cipher_key']
    pub_peer_sign = pub_keys['sign_key']
    signature = pub_keys['message']
    # print("[R] Emitter pub_key_cipher: " +str(pub_peer_cipher))
    # print("[R] Emitter pub_key_sign: " +str(pub_peer_sign))
    # print("[R] Receiver signature: " +str(signature))
    
    try:
        ## Obter a chave pública (Assinatura)
        peer_sign_pubkey = ed448.Ed448PublicKey.from_public_bytes(pub_peer_sign)
        
        ## Validar a correçaõ da assinatura
        peer_sign_pubkey.verify(signature, pub_peer_cipher)
        print("[R] SIGNATURE VALIDATED")
        
        ## Gerar shared keys
        cipher_shared = generateShared(receiver_cipher, pub_peer_cipher)

        ## Enviar as chaves públicas ao peer
        print("[R] SEND PUBLIC KEYS")
        await send(queue, dumps(content))
        
        ## Receber criptograma
        print("[R] AWAIT CIPHER")
        ciphertext = await receive(queue)
        print("[R] CIPHER RECEIVED")

        try:     
            ## Validar a correção da assinatura
            peer_sign_pubkey.verify(ciphertext['sig'], ciphertext['msg'])
            print("[R] SIGNATURE VALIDATED")

            msg_dict = loads(ciphertext['msg'])

            ## Decifrar essa mensagem       
            plain_text, tag_valid = dec_txt(cipher_shared, msg_dict)
            
            if tag_valid == False:
                print("Autenticação falhada!")
                return 
            
            print("[R] MESSAGE DECRYPTED")

            ## Apresentar no terminal
            print("[R] PLAINTEXT: " + plain_text.decode('utf-8'))

            print("[R] END")

        except InvalidSignature:
            print("The signature wasn't validated correctly! - Cipher")
            
    except InvalidSignature:
        print("The signature wasn't validated correctly! - Cipher key")



async def main():
    loop = asyncio.get_event_loop()
    queue = asyncio.Queue(10)
    asyncio.ensure_future(emitter("pls work", queue), loop=loop)
    loop.run_until_complete(receiver(queue))

if __name__ == "__main__":
    asyncio.run(main())