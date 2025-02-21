import os
import json
import hashlib
import base58
from ecdsa import SECP256k1, SigningKey

def generate_keys():
    # Gerar chave privada aleatória
    private_key = os.urandom(32)
    
    # Criar signing key
    signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
    
    # Gerar chave pública com o prefixo 0x04 (não comprimida)
    verifying_key = signing_key.get_verifying_key()
    public_key = b'\x04' + verifying_key.to_string()
    
    return private_key.hex(), public_key.hex()

def generate_address(public_key_hex):
    # Converter hex para bytes
    public_key_bytes = bytes.fromhex(public_key_hex)
    
    # Hash SHA256
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    
    # Hash RIPEMD160 
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    # Prefixo da rede principal (63 decimal = 0x3F)
    version_prefix = bytes([63])
    
    # Adicionar prefixo da versão
    versioned_hash = version_prefix + ripemd160_hash
    
    # Codificar em Base58Check
    address = base58.b58encode_check(versioned_hash)
    
    return address.decode()

def private_key_to_sperocoin(private_key_hex):
    # Converter hex para bytes
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # Prefixo para chave privada (63 + 128 = 191)
    version_prefix = bytes([191])
    
    # Adicionar prefixo
    versioned_private = version_prefix + private_key_bytes
    
    # Codificar em Base58Check
    wif = base58.b58encode_check(versioned_private)
    
    return wif.decode()

def save_to_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
# Gerar novo par de chaves
private_key, public_key = generate_keys()

def main():
    # Quantos endereços você deseja gerar?
    num_addresses = int(input("How many addresses do you want to generate? "))
    
    # Crie um dicionário para armazenar as informações
    addresses = {}
    
    # Gere os endereços e seus dados
    for i in range(num_addresses):
        private_key, public_key = generate_keys()
        address = generate_address(public_key)
        wif = private_key_to_sperocoin(private_key)
        addresses[f"address_{i+1}"] = {
            "private_key": private_key,
            "public_key": public_key,
            "address": address,
            "wif": wif,
            "import": "importprivkey " + wif + " address_offline_" + str(i+1) + " false"
        }
    
    # Salve no arquivo .json
    save_to_json(addresses, "addresses.json")
# Gerar endereço e WIF
address = generate_address(public_key)
wif = private_key_to_sperocoin(private_key)

if __name__ == "__main__":
    main()
print("Address generated successfully!")
