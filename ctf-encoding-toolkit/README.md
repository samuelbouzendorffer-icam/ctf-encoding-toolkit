# ctf-encoding-toolkit

Boîte à outils en Python (bibliothèque standard) pour les **décodages courants des CTF** et le **XOR à clé d'un octet**.

Les épreuves de CTF cachent souvent un message derrière plusieurs couches d'encodage. Cet outil les décode une à une, ou les enchaîne automatiquement.

> Encoder n'est pas chiffrer : Base64, hexadécimal ou binaire sont réversibles par n'importe qui, sans clé.

## Utilisation

```bash
python3 ctf_encoding.py decode --type base64 "SGVsbG8gIQ=="
# Hello !

python3 ctf_encoding.py auto "NjY2YzYxNjc3YjYzNmY3NTYzNjg2NTczN2Q="
# base64 -> hex                flag{couches}
# base64                       666c61677b636f75636865737d

python3 ctf_encoding.py xor-crack 664f0a474f59594b4d4f0a4f595e0a494b49424f0a4e4f5858434f584f0a5f440a7265780a4b0a5f440a45495e4f5e
# casse un XOR à clé d'un octet (texte donné en hexadécimal)
```

Exemple de `xor-crack` (message chiffré avec la clé `0x2a`) :

```
clé 0x2a (*)  score  1.87 : Le message est cache derriere un XOR a un octet
clé 0x2b (+)  score  1.46 : Md!ldrr`fd!dru!b`bid!edsshdsd!to!YNS!`!to!nbudu
```

Décodeurs disponibles : `base64`, `base32`, `hex`, `bin` (binaire), `url`, `rot13`.

## Concepts illustrés

- Encodage, chiffrement et hachage : trois choses différentes.
- **Exploration enchaînée** des décodages, avec profondeur limitée, et classement des résultats qui contiennent un drapeau (`flag{...}`, `CTF{...}`, `HTB{...}`).
- **XOR** : chiffrement réversible avec la même clé, et attaque par force brute des 256 clés possibles, notée par la ressemblance du résultat avec du texte lisible.
- ROT13 produit toujours du texte lisible : il n'est donc retenu dans le mode automatique que s'il révèle un drapeau absent du texte de départ.

## Tests

```bash
python3 -m unittest -v
```

## Limites

La notation du XOR demande un texte d'une vingtaine de caractères au moins. Seuls des textes en français ou en anglais sont reconnus. Les préfixes de drapeaux reconnus sont dans `FLAG_PREFIXES` (à compléter selon le CTF).

## Pistes d'amélioration

- XOR avec une clé de plusieurs octets (recherche de la longueur de clé).
- Ajouter Base58, Base85, le code Morse, le chiffre de Bacon.
- Lire un fichier en entrée plutôt qu'un argument.

## Licence

MIT, voir [LICENSE](LICENSE).

---

