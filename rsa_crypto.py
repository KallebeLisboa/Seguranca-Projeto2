import hashlib
import os
import base64
from rsa_keygen import mod_exp, import_public_key, import_private_key

# -----------------------------------------------------------------------------
# 1. FUNÇÕES AUXILIARES E CONVERSÕES (RFC 8017)
# -----------------------------------------------------------------------------

def i2osp(x: int, x_len: int) -> bytes:
    """Integer-to-Octet-String: Converte um inteiro para uma sequência de bytes."""
    try:
        return x.to_bytes(x_len, byteorder='big')
    except OverflowError:
        raise ValueError("Inteiro demasiado grande para o tamanho especificado.")

def os2ip(x: bytes) -> int:
    """Octet-String-to-Integer: Converte uma sequência de bytes para inteiro."""
    return int.from_bytes(x, byteorder='big')

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Aplica a operação XOR byte a byte."""
    return bytes(x ^ y for x, y in zip(a, b))

def mgf1(seed: bytes, mask_len: int) -> bytes:
    """
    Mask Generation Function (MGF1) utilizando SHA3-256.
    Gera uma máscara de tamanho arbitrário a partir de uma semente inicial.
    """
    t = b''
    for counter in range((mask_len + 31) // 32):
        c = i2osp(counter, 4)
        t += hashlib.sha3_256(seed + c).digest()
    return t[:mask_len]

# -----------------------------------------------------------------------------
# 2. PARTE II - CIFRAGEM E DECIFRAGEM RSA-OAEP
# -----------------------------------------------------------------------------

def rsa_oaep_encrypt(pub_key: dict, message: bytes, label: bytes = b"") -> bytes:
    """Cifra uma mensagem curta utilizando RSA-OAEP com SHA3-256."""
    k = pub_key['key_size_bits'] // 8
    h_len = 32 # Tamanho do SHA3-256
    
    if len(message) > k - 2 * h_len - 2:
        raise ValueError("Mensagem demasiado longa para os parâmetros definidos.")
    
    l_hash = hashlib.sha3_256(label).digest()
    ps = b'\x00' * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b'\x01' + message
    
    seed = os.urandom(h_len)
    db_mask = mgf1(seed, k - h_len - 1)
    masked_db = xor_bytes(db, db_mask)
    
    seed_mask = mgf1(masked_db, h_len)
    masked_seed = xor_bytes(seed, seed_mask)
    
    em = b'\x00' + masked_seed + masked_db
    m_int = os2ip(em)
    c_int = mod_exp(m_int, pub_key['e'], pub_key['n'])
    
    return i2osp(c_int, k)

def rsa_oaep_decrypt(priv_key: dict, ciphertext: bytes, label: bytes = b"") -> bytes:
    """Decifra um criptograma RSA-OAEP e deteta adulterações ou erros de padding."""
    k = priv_key['key_size_bits'] // 8
    h_len = 32
    
    if len(ciphertext) != k:
        raise ValueError("Erro de decifragem: tamanho do criptograma inválido.")
    
    c_int = os2ip(ciphertext)
    m_int = mod_exp(c_int, priv_key['d'], priv_key['n'])
    em = i2osp(m_int, k)
    
    l_hash = hashlib.sha3_256(label).digest()
    y = em[0]
    masked_seed = em[1:h_len + 1]
    masked_db = em[h_len + 1:]
    
    seed_mask = mgf1(masked_db, h_len)
    seed = xor_bytes(masked_seed, seed_mask)
    
    db_mask = mgf1(seed, k - h_len - 1)
    db = xor_bytes(masked_db, db_mask)
    
    l_hash_prime = db[:h_len]
    
    # Validação do padding de forma a evitar ataques de temporização (exigência de segurança)
    if y != 0 or l_hash_prime != l_hash:
        raise ValueError("Erro de decifragem: Padding OAEP inválido ou dados adulterados.")
        
    try:
        separator_idx = db.index(b'\x01', h_len)
    except ValueError:
        raise ValueError("Erro de decifragem: Separador de padding não encontrado.")
        
    return db[separator_idx + 1:]

# -----------------------------------------------------------------------------
# 3. PARTE III - ASSINATURA DIGITAL RSA-PSS
# -----------------------------------------------------------------------------

def rsa_pss_sign(priv_key: dict, file_data: bytes) -> str:
    """
    Gera a assinatura digital de um ficheiro utilizando RSA-PSS e SHA3-256.
    A representação devolvida encontra-se codificada em Base64.
    """
    m_hash = hashlib.sha3_256(file_data).digest()
    h_len = 32
    s_len = 32 # Tamanho do salt
    em_len = (priv_key['key_size_bits'] - 1 + 7) // 8
    
    salt = os.urandom(s_len)
    m_prime = b'\x00' * 8 + m_hash + salt
    h = hashlib.sha3_256(m_prime).digest()
    
    ps = b'\x00' * (em_len - s_len - h_len - 2)
    db = ps + b'\x01' + salt
    
    db_mask = mgf1(h, em_len - h_len - 1)
    masked_db = xor_bytes(db, db_mask)
    
    # Força o bit mais significativo a 0 conforme a especificação do PSS
    masked_db_list = bytearray(masked_db)
    masked_db_list[0] &= 0xFF >> (8 * em_len - (priv_key['key_size_bits'] - 1))
    masked_db = bytes(masked_db_list)
    
    em = masked_db + h + b'\xbc'
    m_int = os2ip(em)
    s_int = mod_exp(m_int, priv_key['d'], priv_key['n'])
    
    signature = i2osp(s_int, priv_key['key_size_bits'] // 8)
    return base64.b64encode(signature).decode('ascii')

def rsa_pss_verify(pub_key: dict, file_data: bytes, signature_b64: str) -> bool:
    """Verifica uma assinatura RSA-PSS contra os dados fornecidos."""
    signature = base64.b64decode(signature_b64)
    k = pub_key['key_size_bits'] // 8
    h_len = 32
    s_len = 32
    em_len = (pub_key['key_size_bits'] - 1 + 7) // 8
    
    if len(signature) != k:
        return False
        
    s_int = os2ip(signature)
    m_int = mod_exp(s_int, pub_key['e'], pub_key['n'])
    em = i2osp(m_int, em_len)
    
    m_hash = hashlib.sha3_256(file_data).digest()
    
    if em[-1] != 0xbc:
        return False
        
    masked_db = em[:em_len - h_len - 1]
    h = em[em_len - h_len - 1:-1]
    
    if masked_db[0] & (0xFF << (8 - (8 * em_len - (pub_key['key_size_bits'] - 1)))):
        return False
        
    db_mask = mgf1(h, em_len - h_len - 1)
    db = bytearray(xor_bytes(masked_db, db_mask))
    db[0] &= 0xFF >> (8 * em_len - (pub_key['key_size_bits'] - 1))
    db = bytes(db)
    
    if db[:em_len - h_len - s_len - 2] != b'\x00' * (em_len - h_len - s_len - 2) or db[em_len - h_len - s_len - 2] != 0x01:
        return False
        
    salt = db[-s_len:]
    m_prime = b'\x00' * 8 + m_hash + salt
    h_prime = hashlib.sha3_256(m_prime).digest()
    
    return h == h_prime