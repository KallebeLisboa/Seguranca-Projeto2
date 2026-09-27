"""Parte IV: estrutura assinada JSON e interface de demonstração."""
import argparse
import base64
import binascii
import json
from pathlib import Path

from rsa_crypto import rsa_pss_sign, rsa_pss_verify
from rsa_keygen import (
    KeyFormatError, export_private_key, export_public_key, generate_keypair,
    import_private_key, import_public_key,
)

PROFILE = {
    "format": "CIC0201-SIGNED-v1",
    "algorithm": "RSA-PSS",
    "hash": "SHA3-256",
    "mgf": "MGF1-SHA3-256",
    "salt_length": 32,
}


class SignedFileError(ValueError):
    """Estrutura assinada inválida."""


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SignedFileError(f"Campo repetido: {key}")
        result[key] = value
    return result


def _decode_base64(value):
    if not isinstance(value, str):
        raise SignedFileError("Campo Base64 deve ser texto.")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SignedFileError("Base64 inválido.") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise SignedFileError("Base64 não canônico.")
    return raw


def serialize_signed_file(file_data: bytes, private_key: dict) -> str:
    """Assina os bytes exatos; nenhuma normalização textual é aplicada."""
    structure = dict(PROFILE)
    structure["content_b64"] = base64.b64encode(file_data).decode("ascii")
    structure["signature_b64"] = rsa_pss_sign(private_key, file_data)
    return json.dumps(structure, indent=2) + "\n"


def parse_signed_file(serialized: str) -> tuple:
    """Recupera conteúdo e assinatura, rejeitando estruturas ambíguas."""
    try:
        structure = json.loads(serialized, object_pairs_hook=_unique_fields)
    except (ValueError, TypeError) as exc:
        raise SignedFileError("Estrutura JSON inválida.") from exc
    if not isinstance(structure, dict) or set(structure) != set(PROFILE) | {
        "content_b64", "signature_b64"
    }:
        raise SignedFileError("Campos da estrutura assinada inválidos.")
    for field, expected in PROFILE.items():
        if type(structure[field]) is not type(expected) or structure[field] != expected:
            raise SignedFileError(f"Parâmetro não suportado: {field}")
    content = _decode_base64(structure["content_b64"])
    if not _decode_base64(structure["signature_b64"]):
        raise SignedFileError("Assinatura vazia.")
    return content, structure["signature_b64"]


def verify_signed_file(serialized: str, public_key: dict) -> bool:
    """Só aceita estrutura válida e assinatura correspondente à chave fornecida."""
    try:
        content, signature = parse_signed_file(serialized)
    except SignedFileError:
        return False
    return rsa_pss_verify(public_key, content, signature)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="Gerar chaves para a demonstração")
    keygen.add_argument("public_key")
    keygen.add_argument("private_key")
    sign = commands.add_parser("sign", help="Assinar arquivo binário ou textual")
    sign.add_argument("file")
    sign.add_argument("private_key")
    sign.add_argument("output")
    verify = commands.add_parser("verify", help="Verificar usando chave pública confiável")
    verify.add_argument("signed_file")
    verify.add_argument("public_key")
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            if Path(args.public_key).resolve() == Path(args.private_key).resolve():
                raise ValueError("Use caminhos distintos para as chaves.")
            public, private = generate_keypair()
            export_public_key(public, args.public_key)
            export_private_key(private, args.private_key)
            print("Par de chaves RSA de 2048 bits gerado.")
        elif args.command == "sign":
            content = Path(args.file).read_bytes()
            private = import_private_key(args.private_key)
            Path(args.output).write_text(serialize_signed_file(content, private), encoding="utf-8")
            print("Estrutura assinada salva.")
        else:
            public = import_public_key(args.public_key)
            serialized = Path(args.signed_file).read_text(encoding="utf-8")
            if not verify_signed_file(serialized, public):
                print("Assinatura inválida: arquivo, estrutura ou chave não correspondem.")
                return 1
            print("Arquivo íntegro: assinatura RSA-PSS válida para a chave pública fornecida.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, ArithmeticError) as exc:
        prefix = "Verificação rejeitada" if args.command == "verify" else "Operação rejeitada"
        print(f"{prefix}: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
