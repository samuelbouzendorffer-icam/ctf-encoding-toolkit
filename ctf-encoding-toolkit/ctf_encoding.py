#!/usr/bin/env python3
"""ctf_encoding : décodages courants des CTF et XOR à clé d'un octet.

Les épreuves de CTF cachent souvent un message derrière plusieurs couches d'encodage
(Base64, hexadécimal, binaire...). Attention : encoder n'est PAS chiffrer, ces
transformations sont réversibles par n'importe qui, sans clé.
"""
import argparse
import base64
import binascii
import re
import string
import urllib.parse

PRINTABLE = set(string.printable)
# Préfixes de drapeaux courants (à compléter avec celui de votre CTF).
FLAG_PREFIXES = ("flag", "ctf", "htb", "thm", "picoctf")
FLAG_RE = re.compile(r"\b(?:" + "|".join(FLAG_PREFIXES) + r")\{[^}\s]{1,80}\}", re.IGNORECASE)


# ----- décodeurs : str -> str (lèvent ValueError si le texte n'est pas valide) -----
def dec_base64(s):
    return base64.b64decode(s.strip(), validate=True).decode("utf-8")


def dec_base32(s):
    return base64.b32decode(s.strip().upper(), casefold=True).decode("utf-8")


def dec_hex(s):
    cleaned = re.sub(r"[\s:]|0x", "", s)
    try:
        return bytes.fromhex(cleaned).decode("utf-8")
    except ValueError as err:
        raise ValueError(str(err))


def dec_binary(s):
    bits = re.sub(r"\s", "", s)
    if not bits or set(bits) - {"0", "1"} or len(bits) % 8:
        raise ValueError("binaire invalide")
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)).decode("utf-8")


def dec_url(s):
    out = urllib.parse.unquote(s)
    if out == s:
        raise ValueError("rien à décoder")
    return out


def dec_rot13(s):
    return s.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
        + string.ascii_uppercase[13:] + string.ascii_uppercase[:13]))


DECODERS = {
    "base64": dec_base64, "base32": dec_base32, "hex": dec_hex,
    "bin": dec_binary, "url": dec_url, "rot13": dec_rot13,
}


def is_printable(text: str, ratio: float = 0.95) -> bool:
    return bool(text) and sum(c in PRINTABLE for c in text) / len(text) >= ratio


def auto_decode(text: str, depth: int = 3) -> list:
    """Explore les décodages enchaînés. Retourne [(chaîne_de_décodeurs, résultat)]."""
    results, seen = [], {text}
    frontier = [((), text)]
    for _ in range(depth):
        nxt = []
        for chain, current in frontier:
            for name, fn in DECODERS.items():
                try:
                    out = fn(current)
                except (ValueError, binascii.Error, UnicodeDecodeError):
                    continue
                # ROT13 produit toujours du texte "lisible" : on ne le garde que s'il révèle
                # un drapeau absent du texte d'origine.
                if name == "rot13" and (FLAG_RE.search(current) or not FLAG_RE.search(out)):
                    continue
                if out in seen or not is_printable(out):
                    continue
                seen.add(out)
                nxt.append((chain + (name,), out))
        results.extend(nxt)
        frontier = nxt
    # les résultats contenant un drapeau (flag{...}) d'abord, puis les chaînes courtes
    return sorted(results, key=lambda r: (not FLAG_RE.search(r[1]), len(r[0])))


def find_flags(text: str) -> list:
    return FLAG_RE.findall(text)


# ----- XOR -----
def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("clé vide")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _english_score(data: bytes) -> float:
    """Plus le score est élevé, plus le texte ressemble à de l'anglais ou du français."""
    score = 0.0
    for b in data:
        c = chr(b)
        if c in "etaoinshrdlu ETAOINSHRDLU":
            score += 2
        elif c.isalpha():
            score += 1
        elif c in " .,'!?-:;0123456789\n":
            score += 0.5
        elif c not in PRINTABLE:
            score -= 5
    return score / max(len(data), 1)


def xor_single_byte_crack(data: bytes, top: int = 3) -> list:
    """Teste les 256 clés d'un octet. Retourne [(clé, texte, score)] meilleurs d'abord."""
    candidates = []
    for key in range(256):
        plain = xor_bytes(data, bytes([key]))
        candidates.append((key, plain.decode("latin-1"), _english_score(plain)))
    return sorted(candidates, key=lambda c: -c[2])[:top]


def main() -> None:
    parser = argparse.ArgumentParser(description="Décodages de CTF et XOR.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("decode", help="décode avec un décodeur précis")
    p.add_argument("--type", choices=sorted(DECODERS), required=True); p.add_argument("text")
    p = sub.add_parser("auto", help="essaie les décodages enchaînés")
    p.add_argument("--depth", type=int, default=3); p.add_argument("text")
    p = sub.add_parser("xor-crack", help="casse un XOR à clé d'un octet (texte en hexadécimal)")
    p.add_argument("hexdata")
    p = sub.add_parser("xor", help="applique un XOR avec une clé texte (hexadécimal en entrée et en sortie)")
    p.add_argument("--key", required=True); p.add_argument("hexdata")
    args = parser.parse_args()

    try:
        if args.command == "decode":
            print(DECODERS[args.type](args.text))
        elif args.command == "auto":
            found = auto_decode(args.text, args.depth)
            if not found:
                print("Aucun décodage lisible trouvé.")
            for chain, out in found[:5]:
                print(f"{' -> '.join(chain):<28} {out}")
        elif args.command == "xor-crack":
            for key, text, score in xor_single_byte_crack(bytes.fromhex(args.hexdata)):
                print(f"clé 0x{key:02x} ({chr(key) if 32 <= key < 127 else '?'})  score {score:5.2f} : {text}")
        else:
            print(xor_bytes(bytes.fromhex(args.hexdata), args.key.encode()).hex())
    except (ValueError, binascii.Error, UnicodeDecodeError) as err:
        raise SystemExit(f"Erreur : {err}")


if __name__ == "__main__":
    main()
