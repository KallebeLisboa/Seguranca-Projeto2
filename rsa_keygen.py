"""
Este módulo implementa, de forma totalmente manual, os componentes matemáticos
necessários para gerar um par de chaves RSA seguro:

    1. Aritmética modular (exponenciação rápida e inverso modular via Algoritmo Estendido de Euclides)
    2. Teste de primalidade probabilístico de Miller-Rabin
    3. Geração de primos grandes usando aleatoriedade criptograficamente segura
    4. Geração do par de chaves RSA (>= 2048 bits), incluindo os parâmetros CRT (dP, dQ, qInv)
    usados por outras partes do projeto para acelerar operações com a chave privada
    5. Serialização (export) e desserialização (import) das chaves em
    um formato JSON próprio, com validação de integridade
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Dict, Tuple

# 1. ARITMÉTICA MODULAR MANUAL

def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Square-and-multiply

    Calcula (base ** exp) % mod usando apenas multiplicações e módulos, em tempo O(log exp)
    """

    if any(type(v) is not int for v in (base, exp, mod)) or exp < 0 or mod <= 0:
        raise ValueError("Exponenciação exige inteiros, expoente não negativo e módulo positivo.")
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Algoritmo Estendido de Euclides.

    Retorna a tupla (g, x, y) tal que a*x + b*y = g = mdc(a, b)
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quociente = old_r // r
        old_r, r = r, old_r - quociente * r
        old_s, s = s, old_s - quociente * s
        old_t, t = t, old_t - quociente * t
    return old_r, old_s, old_t


def gcd(a: int, b: int) -> int:
    """
    Máximo divisor comum (Euclides simples)
    """
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a: int, m: int) -> int:
    """
    Inverso multiplicativo de a mod m, via Euclides Estendido.

    Lança ValueError se o inverso não existir (isto é, se mdc(a, m) != 1).
    """
    if type(a) is not int or type(m) is not int or m <= 1:
        raise ValueError("Inverso exige inteiros e módulo maior que 1.")
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Inverso modular inexistente: mdc({a}, {m}) = {g}")
    return x % m

# 2. TESTE DE PRIMALIDADE DE MILLER-RABIN

# Pequenos primos usados para um "crivo" rápido antes do teste probabilístico,
# eliminando a maioria dos candidatos compostos sem custo de exponenciação.
_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
                109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
                173, 179, 181, 191, 193, 197, 199)


def is_probable_prime(n: int, rounds: int = 20) -> bool:
    """Teste de primalidade probabilístico de Miller-Rabin

    Parâmetros:
        n: número ímpar (> 2) a ser testado.
        rounds: número de rodadas com testemunhas aleatórias. A probabilidade
            de um composto ser erroneamente aceito como primo é, no pior caso, <= 4^(-rounds)

    Retorna:
        True  -> n é provavelmente primo.
        False -> n é certamente composto.
    """

    if type(n) is not int or type(rounds) is not int or rounds < 1:
        raise ValueError("Miller-Rabin exige inteiro e ao menos uma rodada.")
    if n < 2:
        return False
    if n in _SMALL_PRIMES:
        return True
    if any(n % p == 0 for p in _SMALL_PRIMES):
        return False

    # Escreve n - 1 = 2^s * d, com d ímpar
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        # Testemunha aleatória no intervalo [2, n - 2]
        a = secrets.randbelow(n - 3) + 2
        x = mod_exp(a, d, n)

        if x == 1 or x == n - 1:
            continue  # esta testemunha não detectou composição

        for _ in range(s - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            # nenhuma iteração satisfez x == n-1: n é composto
            return False

    return True  # provavelmente primo em todas as rodadas

# 3. GERAÇÃO DE PRIMOS GRANDES

def generate_prime(bits: int, rounds: int = 20) -> int:
    """
    Gera um número primo (provável) com exatamente `bits` bits.

    Usa secrets.randbits para gerar candidatos aleatórios seguros, fixa
    os dois bits mais significativos (garante que o produto p*q tenha o
    número de bits esperado) e o bit menos significativo (garante que o
    número é ímpar), testando cada candidato com Miller-Rabin.
    """
    if type(rounds) is not int or rounds < 1:
        raise ValueError("O número de rodadas deve ser inteiro positivo.")
    if type(bits) is not int or bits < 8:
        raise ValueError("bits deve ser >= 8 para geração de primos RSA.")

    while True:
        candidate = secrets.randbits(bits)
        '''Fixa os dois bits mais altos -> garante bit_length == bits e ajuda a garantir que o 
        produto de dois primos deste tamanho tenha, no mínimo, 2*bits - 1 bits (evita módulos "curtos").
        '''
        candidate |= (1 << (bits - 1)) | (1 << (bits - 2))
        candidate |= 1  # garante número ímpar
        if is_probable_prime(candidate, rounds):
            return candidate


# 4. GERAÇÃO DO PAR DE CHAVES RSA

DEFAULT_PUBLIC_EXPONENT = 65537  # expoente público padrão (F4 = 2^16 + 1)


def generate_keypair(key_size_bits: int = 2048, e: int = DEFAULT_PUBLIC_EXPONENT, 
                    miller_rabin_rounds: int = 20) -> Tuple[Dict, Dict]:
    """
    Gera um par de chaves RSA (chave_publica, chave_privada).

    Parâmetros:
        key_size_bits: tamanho mínimo do módulo n, em bits (mínimo 2048,
            conforme exigido pelo enunciado do trabalho).
        e: expoente público (deve ser primo em relação a phi(n)).
        miller_rabin_rounds: rodadas do teste de primalidade.

    Retorna:
        (chave_publica, chave_privada), cada uma como um dicionário
        contendo os parâmetros RSA relevantes (todos como inteiros).
    """
    if type(miller_rabin_rounds) is not int or miller_rabin_rounds < 1:
        raise ValueError("O número de rodadas deve ser inteiro positivo.")
    if type(key_size_bits) is not int or key_size_bits < 2048:
        raise ValueError("O módulo RSA deve ter, no mínimo, 2048 bits.")
    if type(e) is not int or e < 3 or e % 2 == 0 or e.bit_length() > key_size_bits:
        raise ValueError("Expoente público 'e' inválido (deve ser ímpar e >= 3).")

    half = key_size_bits // 2
    other_half = key_size_bits - half

    while True:
        p = generate_prime(half, miller_rabin_rounds)
        q = generate_prime(other_half, miller_rabin_rounds)

        if p == q:
            continue  # p e q precisam ser distintos

        n = p * q
        if n.bit_length() < key_size_bits or e >= n:
            continue  # produto ficou curto por azar na geração. Tenta de novo

        phi = (p - 1) * (q - 1)  # função totiente de Euler

        if gcd(e, phi) != 1:
            continue  # e precisa ser coprimo com phi(n)

        d = mod_inverse(e, phi)
        break

    '''
    Parâmetros do Teorema Chinês do Resto (CRT), usados para acelerar 
    operações com a chave privada (decifragem OAEP / assinatura PSS).
    '''

    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = mod_inverse(q, p)

    private_key = {
        "n": n, "e": e, "d": d,
        "p": p, "q": q,
        "dp": dp, "dq": dq, "qinv": q_inv,
        "key_size_bits": key_size_bits,
    }
    public_key = {
        "n": n, "e": e,
        "key_size_bits": key_size_bits,
    }
    return public_key, private_key

# 5. FORMATO DE IMPORTAÇÃO / EXPORTAÇÃO DE CHAVES

'''
As chaves são serializadas em JSON. Cada parâmetro inteiro grande (n, e, d, p, q, ...) 
é convertido para bytes (big-endian) e então codificado em Base64, evitando problemas de 
precisão/portabilidade que números inteiros gigantes poderiam causar em outros parsers JSON.

- Estrutura do arquivo de CHAVE PÚBLICA (formato "CIC0201-RSA-PUB-v1"):
{
    "format": "CIC0201-RSA-PUB-v1",
    "algorithm": "RSA",
    "key_size_bits": 2048,
    "n": "<base64>",
    "e": "<base64>",
    "created_at": "2026-09-22T12:00:00Z"
}

- Estrutura do arquivo de CHAVE PRIVADA (formato "CIC0201-RSA-PRIV-v1"):
{
    "format": "CIC0201-RSA-PRIV-v1",
    "algorithm": "RSA",
    "key_size_bits": 2048,
    "n": "<base64>", "e": "<base64>", "d": "<base64>",
    "p": "<base64>", "q": "<base64>",
    "dp": "<base64>", "dq": "<base64>", "qinv": "<base64>",
    "created_at": "2026-09-22T12:00:00Z"
}

O campo "format" funciona como um "número mágico" simplificado: ele é
checado em toda importação para rejeitar arquivos incompatíveis ou de
outra origem antes mesmo de tentar decodificar os números.
'''

PUBLIC_KEY_FORMAT = "CIC0201-RSA-PUB-v1"
PRIVATE_KEY_FORMAT = "CIC0201-RSA-PRIV-v1"


class KeyFormatError(ValueError):
    """
    Erro lançado quando um arquivo de chave está ausente, mal formado,
    incompleto ou falha em uma verificação de consistência matemática
    (indício de corrupção ou adulteração).
    """


def _int_to_b64(value: int) -> str:
    length = max((value.bit_length() + 7) // 8, 1)
    return base64.b64encode(value.to_bytes(length, byteorder="big")).decode("ascii")


def _b64_to_int(text: str) -> int:
    if not isinstance(text, str):
        raise ValueError("Parâmetro Base64 deve ser texto.")
    raw = base64.b64decode(text, validate=True)
    if not raw or base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("Base64 vazio ou não canônico.")
    return int.from_bytes(raw, byteorder="big")


def _timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def export_public_key(public_key: Dict, filepath: str) -> None:
    '''Exporta uma chave pública para um arquivo JSON no formato definido.'''
    data = {
        "format": PUBLIC_KEY_FORMAT,
        "algorithm": "RSA",
        "key_size_bits": public_key["key_size_bits"],
        "n": _int_to_b64(public_key["n"]),
        "e": _int_to_b64(public_key["e"]),
        "created_at": _timestamp(),
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def export_private_key(private_key: Dict, filepath: str) -> None:
    '''Exporta uma chave privada (com parâmetros CRT) para um arquivo JSON.'''
    data = {
        "format": PRIVATE_KEY_FORMAT,
        "algorithm": "RSA",
        "key_size_bits": private_key["key_size_bits"],
        "n": _int_to_b64(private_key["n"]),
        "e": _int_to_b64(private_key["e"]),
        "d": _int_to_b64(private_key["d"]),
        "p": _int_to_b64(private_key["p"]),
        "q": _int_to_b64(private_key["q"]),
        "dp": _int_to_b64(private_key["dp"]),
        "dq": _int_to_b64(private_key["dq"]),
        "qinv": _int_to_b64(private_key["qinv"]),
        "created_at": _timestamp(),
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _unique_fields(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise KeyFormatError(f"Campo repetido: {key}")
        data[key] = value
    return data


def validate_public_key(key: Dict) -> None:
    """Valida estrutura e limites; não certifica a identidade do proprietário."""
    if not isinstance(key, dict) or any(
        type(key.get(field)) is not int for field in ("n", "e", "key_size_bits")
    ):
        raise KeyFormatError("Parâmetros públicos devem ser inteiros.")
    n, e, bits = key["n"], key["e"], key["key_size_bits"]
    if n <= 0 or n % 2 == 0 or n.bit_length() < 2048:
        raise KeyFormatError("Módulo RSA deve ser ímpar e ter ao menos 2048 bits.")
    if bits != n.bit_length():
        raise KeyFormatError("Tamanho declarado não corresponde ao módulo.")
    if not 3 <= e < n or e % 2 == 0:
        raise KeyFormatError("Expoente público inválido.")


def _load_json(filepath: str) -> Dict:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f, object_pairs_hook=_unique_fields)
            if not isinstance(data, dict):
                raise KeyFormatError("A chave deve ser um objeto JSON.")
            return data
    except FileNotFoundError as exc:
        raise KeyFormatError(f"Arquivo de chave não encontrado: {filepath}") from exc
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise KeyFormatError(f"Arquivo de chave não é um JSON válido: {exc}") from exc


def import_public_key(filepath: str) -> Dict:
    '''Importa e valida uma chave pública a partir de um arquivo JSON.'''
    data = _load_json(filepath)

    required_fields = {"format", "algorithm", "n", "e", "key_size_bits"}
    if not required_fields.issubset(data):
        faltando = required_fields - set(data)
        raise KeyFormatError(f"Campos obrigatórios ausentes na chave pública: {faltando}")

    if data["format"] != PUBLIC_KEY_FORMAT or data["algorithm"] != "RSA":
        raise KeyFormatError(f"Formato de chave pública não reconhecido: {data['format']!r}")

    try:
        n = _b64_to_int(data["n"])
        e = _b64_to_int(data["e"])
    except Exception as exc:
        raise KeyFormatError(f"Falha ao decodificar parâmetros da chave: {exc}") from exc

    key = {"n": n, "e": e, "key_size_bits": data["key_size_bits"]}
    validate_public_key(key)
    return key


def import_private_key(filepath: str) -> Dict:
    '''
    Importa e valida uma chave privada a partir de um arquivo JSON.

    Além de checar os campos obrigatórios, valida a consistência
    matemática da chave (p*q == n e e*d == 1 mod phi(n)), detectando
    arquivos corrompidos ou adulterados.
    '''
    data = _load_json(filepath)

    required_fields = {"format", "algorithm", "n", "e", "d", "p", "q", "dp", "dq", "qinv", "key_size_bits"}
    if not required_fields.issubset(data):
        raise KeyFormatError("Campos obrigatórios ausentes na chave privada.")
    if data["format"] != PRIVATE_KEY_FORMAT or data["algorithm"] != "RSA":
        raise KeyFormatError("Formato ou algoritmo da chave privada inválido.")
    try:
        valores = {campo: _b64_to_int(data[campo])
                   for campo in ("n", "e", "d", "p", "q", "dp", "dq", "qinv")}
    except (ValueError, TypeError) as exc:
        raise KeyFormatError("Parâmetro privado não é Base64 válido.") from exc

    valores["key_size_bits"] = data["key_size_bits"]
    validate_public_key(valores)
    n, e, d = valores["n"], valores["e"], valores["d"]
    p, q = valores["p"], valores["q"]
    # Limites antes de qualquer módulo por p-1, q-1 ou phi.
    if not (3 <= p < n and 3 <= q < n) or p == q or p % 2 == 0 or q % 2 == 0:
        raise KeyFormatError("Fatores privados inválidos.")
    if p * q != n:
        raise KeyFormatError("Chave corrompida: p * q != n.")
    phi = (p - 1) * (q - 1)
    # O formato do grupo armazena d como o inverso canônico módulo phi.
    if not 0 < d < phi or (e * d) % phi != 1:
        raise KeyFormatError("Expoente privado inconsistente com phi(n).")
    if valores["dp"] != d % (p - 1) or valores["dq"] != d % (q - 1):
        raise KeyFormatError("Parâmetros CRT dp/dq inconsistentes.")
    if not 0 < valores["qinv"] < p or (q * valores["qinv"]) % p != 1:
        raise KeyFormatError("Parâmetro CRT qinv inconsistente.")
    # Relações algébricas isoladas não garantem que os fatores sejam primos.
    if not is_probable_prime(p) or not is_probable_prime(q):
        raise KeyFormatError("Fatores privados compostos.")

    return valores


# 6. DEMONSTRAÇÃO / AUTOTESTE

if __name__ == "__main__":
    print("=== Parte I - Geração e Gerenciamento de Chaves RSA ===\n")

    print("Gerando par de chaves RSA de 2048 bits...")
    inicio = time.time()
    chave_publica, chave_privada = generate_keypair(key_size_bits=2048)
    fim = time.time()
    print(f"  -> Chaves geradas em {fim - inicio:.2f} segundos.")
    print(f"  -> n possui {chave_publica['n'].bit_length()} bits.\n")

    print("Exportando chaves para arquivos JSON...")
    export_public_key(chave_publica, "chave_publica.json")
    export_private_key(chave_privada, "chave_privada.json")
    print("  -> chave_publica.json e chave_privada.json gerados.\n")

    print("Importando chaves de volta e validando round-trip...")
    pub_importada = import_public_key("chave_publica.json")
    priv_importada = import_private_key("chave_privada.json")

    assert pub_importada["n"] == chave_publica["n"]
    assert pub_importada["e"] == chave_publica["e"]
    assert priv_importada["d"] == chave_privada["d"]
    print("  -> Round-trip de importação/exportação OK.\n")

    print("Testando teste rápido de assinatura/verificação bruta (sem padding)")
    print("apenas para validar que d e e são realmente inversos módulo n:")
    m = 424242
    c = mod_exp(m, chave_publica["e"], chave_publica["n"])
    m_de_volta = mod_exp(c, chave_privada["d"], chave_privada["n"])
    assert m == m_de_volta
    print(f"  -> mensagem {m} -> cifrado -> decifrado -> {m_de_volta} (OK)\n")

    print("Testando detecção de arquivo de chave incompleto/corrompido...")
    dados_corrompidos = json.load(open("chave_publica.json", encoding="utf-8"))
    del dados_corrompidos["e"]
    with open("chave_publica_corrompida.json", "w", encoding="utf-8") as f:
        json.dump(dados_corrompidos, f)

    try:
        import_public_key("chave_publica_corrompida.json")
        print("  -> ERRO: a chave corrompida NÃO foi detectada!")
    except KeyFormatError as exc:
        print(f"  -> Chave incompleta detectada corretamente: {exc}\n")

    print("Todos os testes passaram com sucesso.")
