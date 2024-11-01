# hash_signatures.py
# You can add more signatures here
hash_signatures = {
    # MD Family
    "md2": {
        "length": 32,
        "characters": r"^[a-f0-9]{32}$",
        "example": "dffb752bfc4be8de5eaee4bd34a7f8d1"
    },
    "md4": {
        "length": 32,
        "characters": r"^[a-f0-9]{32}$",
        "example": "a5f3c6a11b03839d46af9fb43c97c188"
    },
    "md5": {
        "length": 32,
        "characters": r"^[a-f0-9]{32}$",
        "example": "5d41402abc4b2a76b9719d911017c592"
    },

    # SHA Family
    "sha1": {
        "length": 40,
        "characters": r"^[a-f0-9]{40}$",
        "example": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
    },
    "sha224": {
        "length": 56,
        "characters": r"^[a-f0-9]{56}$",
        "example": "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    },
    "sha256": {
        "length": 64,
        "characters": r"^[a-f0-9]{64}$",
        "example": "d2d2d2d2e957e65707e88f7eecb9bc91b138b4f6c793b79923c4b6df3b67f0d2"
    },
    "sha384": {
        "length": 96,
        "characters": r"^[a-f0-9]{96}$",
        "example": "3fed1f814d28dc5d63e313f8a601ecc4836d1662a19365b1f20d7a9c4d50b1d1" \
                    "f1a4f44c016ae0c8b3086b68b1f2db"
    },
    "sha512": {
        "length": 128,
        "characters": r"^[a-f0-9]{128}$",
        "example": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" \
                    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    },

    # SHA3 Family
    "sha3-224": {
        "length": 56,
        "characters": r"^[a-f0-9]{56}$",
        "example": "6b4e03423667dbb73b6e1586bf3d1d77cdf5e3e87daf6d8c92a8f5ae"
    },
    "sha3-256": {
        "length": 64,
        "characters": r"^[a-f0-9]{64}$",
        "example": "a9a1fc9d297d09c1049e59db683d9c6f8f2e3b2e5f1b8bf91c34d54537a1d85d"
    },
    "sha3-384": {
        "length": 96,
        "characters": r"^[a-f0-9]{96}$",
        "example": "6b2c120fb69123e55a3cd5a167c2abef8d219e404033b8e4e2bb32996e6c8f23" \
                    "436f4f15a1b7b4e3b61e8dbedeb6362a"
    },
    "sha3-512": {
        "length": 128,
        "characters": r"^[a-f0-9]{128}$",
        "example": "b751850b1a57168a5693cd92421b7e3d4d05966041a08990c45e485925a72595" \
                    "993b28ee7be7cb01fcbc36ed8fdfb2d6c2a48f8a3c687a9a1aa2a6032924eb3a"
    },

    # Bcrypt
    "bcrypt": {
        "length": 60,
        "characters": r"^\$2[aby]\$.{56}$",
        "example": "$2b$12$eImiTXuWVxfM37uY4JANjQ=="
    },

    # RIPEMD Family
    "ripemd128": {
        "length": 32,
        "characters": r"^[a-f0-9]{32}$",
        "example": "cdf26213a150dc3ecb610f18f6b38b46"
    },
    "ripemd160": {
        "length": 40,
        "characters": r"^[a-f0-9]{40}$",
        "example": "108f07b8382412612c048d07d13f814118445acd"
    },
    "ripemd256": {
        "length": 64,
        "characters": r"^[a-f0-9]{64}$",
        "example": "cc1d2594aece0b8b6e6a7ba6d43b5ecc9dbdbbeef4b4b5930eb10c494a4a88c6"
    },
    "ripemd320": {
        "length": 80,
        "characters": r"^[a-f0-9]{80}$",
        "example": "eb0cf45114c54b4df12fda17e511a56f07b50d012a1f9a95c3a5bb8a"
    },

    # Whirlpool
    "whirlpool": {
        "length": 128,
        "characters": r"^[a-f0-9]{128}$",
        "example": "19fa61d75522a4669b44e4b15af5d89deeb5f5e90d4d6a28a08b788e"
                    "e6f62f3543cd3ffcc96d79b35b818fc0e9c02a0f7db1a8b4c3d122fe0b1a997"
    },

    # CRC Family
    "crc16": {
        "length": 4,
        "characters": r"^[a-f0-9]{4}$",
        "example": "3d0f"
    },
    "crc32": {
        "length": 8,
        "characters": r"^[a-f0-9]{8}$",
        "example": "d87f7e0c"
    },

    # NTLM (used in Windows environments)
    "ntlm": {
        "length": 32,
        "characters": r"^[a-f0-9]{32}$",
        "example": "cc348bace876ea440a28ddaeb9fd3550"
    },

    # Custom Algorithms and Hashes
    "mysql5": {
        "length": 40,
        "characters": r"^[a-f0-9]{40}$",
        "example": "3d9d5e2e4a5956a3492cb2f8bdb152f029f7515c"
    },
    "postgresql_md5": {
        "length": 35,
        "characters": r"^md5[a-f0-9]{32}$",
        "example": "md5f5eebc1559e8c5e6d58c5f7c5d9a6547"
    },

    # LM Hash (Older Windows OS)
    "lm": {
        "length": 32,
        "characters": r"^[a-f0-9]{32}$",
        "example": "aad3b435b51404eeaad3b435b51404ee"
    },

    # Oracle Hashes
    "oracle10g": {
        "length": 16,
        "characters": r"^[a-f0-9]{16}$",
        "example": "d4df03d3fa1c59f7"
    },
    "oracle11g": {
        "length": 48,
        "characters": r"^S:[A-F0-9]{40}$",
        "example": "S:D4DF03D3FA1C59F7AAB28FC2E908FA30"
    },

    # DES-based crypt (Unix)
    "des_crypt": {
        "length": 13,
        "characters": r"^[a-zA-Z0-9./]{13}$",
        "example": "XY7xoYHh3sDsA"
    },

    # Blowfish-based crypt (Unix)
    "blowfish_crypt": {
        "length": 60,
        "characters": r"^\$2[aby]\$.{56}$",
        "example": "$2a$10$C6UzMDM.H6dfI/f/IK/euO1uO9re2z9CuFj2vqj8rh3/pG4u3p.rW"
    },

    # SHA-256-based crypt (Unix)
    "sha256_crypt": {
        "length": 64,
        "characters": r"^\$5\$.{43,}$",
        "example": "$5$rounds=5000$abcdefghijklmnop$eW5MbI39liRj6nZxLbnDz1Z7AaoeD0SBgoDpHUTtxV0"
    },

    # SHA-512-based crypt (Unix)
    "sha512_crypt": {
        "length": 86,
        "characters": r"^\$6\$.{43,}$",
        "example": "$6$rounds=5000$abcdefghijklmnop$9q6wdy8R7Bavh3VVlpQANc6.IXhHk1x8/csiMdjmL8bRl"
    },

    # SSHA (Salted SHA-1 used in LDAP)
    "ssha": {
        "length": 40,
        "characters": r"^\{SSHA\}[a-zA-Z0-9+/]{28}$",
        "example": "{SSHA}k1h8C1u2uF5g5Sogb74o4fP3q5h5kJ6v"
    },

    # SSHA-256 (Salted SHA-256 used in LDAP)
    "ssha256": {
        "length": 48,
        "characters": r"^\{SSHA256\}[a-zA-Z0-9+/]{48}$",
        "example": "{SSHA256}bXJH3u4PfG+8B0so/BRu8Jj9ak9PuwA7m9/m"
    },

    # Django (default MD5)
    "django_md5": {
        "length": 37,
        "characters": r"^md5\$[a-zA-Z0-9\$]{32}$",
        "example": "md5$abcdef123456abcdef123456abcdef12"
    },

    # Django (SHA-1)
    "django_sha1": {
        "length": 46,
        "characters": r"^sha1\$[a-zA-Z0-9\$]{40}$",
        "example": "sha1$abcdef$abcdef123456abcdef123456abcdef123456"
    },

    # vBulletin Hash
    "vbulletin": {
        "length": 35,
        "characters": r"^[a-f0-9]{32}:[a-f0-9]{3,31}$",
        "example": "5d41402abc4b2a76b9719d911017c592:abc"
    },

    # Joomla (MD5-based)
    "joomla_md5": {
        "length": 32,
        "characters": r"^[a-f0-9]{32}:.{16}$",
        "example": "d2064d841d8ca1557c6e9b0141e6b9b5:salt"
    },

    # PHPass (Portable PHP password hashing framework)
    "phpass": {
        "length": 34,
        "characters": r"^\$P\$[a-zA-Z0-9./]{31}$",
        "example": "$P$B6E9JJi2S5eTJc9SNT20RMEL4TDXYp1"
    },

    # ColdFusion (CFMX) Hash
    "cfmx": {
        "length": 32,
        "characters": r"^[a-f0-9]{32}$",
        "example": "425af12a0743502b322e93a015bcf868"
    },

    # Lotus Domino
    "lotus_domino": {
        "length": 16,
        "characters": r"^\([A-Z0-9]{16}\)$",
        "example": "(A94A8FE5CCB19BA6)"
    },

    # SAP CODVN B (SAP passcode)
    "sap_codvn_b": {
        "length": 8,
        "characters": r"^[a-f0-9]{8}$",
        "example": "pass1234"
    },

    # SAP CODVN F/G (BCrypt-based, with SAP specific modifications)
    "sap_codvn_fg": {
        "length": 40,
        "characters": r"^.{40}$",
        "example": "006000A417AB8F67BB4A5A5A67F9174A0A3B"
    },

    # CRC32 (Hexadecimal)
    "crc32_hex": {
        "length": 8,
        "characters": r"^[a-f0-9]{8}$",
        "example": "d87f7e0c"
    },

    # Keccak-256 (Predecessor to SHA-3)
    "keccak256": {
        "length": 64,
        "characters": r"^[a-f0-9]{64}$",
        "example": "a3f09b998b5a2f9f07c3ee9331e39450c5b96fe767a31b31f8de5d61c8e6e100"
    },

    # Ethereum Address (Keccak-256)
    "ethereum_address": {
        "length": 42,
        "characters": r"^0x[a-fA-F0-9]{40}$",
        "example": "0x32Be343B94f860124dC4fEe278FDCBD38C102D88"
    },

    # Bitcoin Address (Base58Check)
    "bitcoin_address": {
        "length": 34,
        "characters": r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
        "example": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    },

    # Scrypt Hash (used by certain web applications and cryptocurrencies)
    "scrypt": {
        "length": 100,
        "characters": r"^\$s0\$e0801\$[a-zA-Z0-9+/]{32}\$[a-zA-Z0-9+/]{32}$",
        "example": "$s0$e0801$Kq5sN9f5aWnUfnLfdQkDeX=="
    },
        # WPA/WPA2 PMKID Hash (used in Wi-Fi handshakes)
    "pmkid": {
        "length": 64,
        "characters": r"^[a-f0-9]{64}$",
        "example": "3c58c1b43b9e3e5d63e938cba7f58b8c0c7f063d4fc23a4cde5b236f6aaf68d8"
    },

    # MySQL SHA1
    "mysql_sha1": {
        "length": 40,
        "characters": r"^[a-f0-9]{40}$",
        "example": "*94bdcebe19083ce2a1f959fd02f964c7af4cfc29"
    },

    # MSSQL 2005 (SHA1 with salt)
    "mssql_2005": {
        "length": 54,
        "characters": r"^0x0100[a-f0-9]{48}$",
        "example": "0x0100A914DDFF5B4D8BAE4B4D4F5AA6A7D7BAF00CDE6B0D"
    },

    # MSSQL 2012+ (SHA512 with salt)
    "mssql_2012": {
        "length": 134,
        "characters": r"^0x0200[a-f0-9]{128}$",
        "example": "0x0200A94DDFF5B4D8BAE4B4D4F5AA6A7D7BAF00CDE6B0D"
    },

    # Oracle 7-10g (DES)
    "oracle_old": {
        "length": 16,
        "characters": r"^[a-f0-9]{16}$",
        "example": "d4df03d3fa1c59f7"
    },

    # Oracle 11g+ (SHA-1 and PBKDF2 with salt)
    "oracle11g_pbkdf2": {
        "length": 60,
        "characters": r"^[a-f0-9]{60}$",
        "example": "S:7812C7F492B87ACAF80F35B2990E833C3F120182C2E9FE660D1BFC08F"
    },

    # PostgreSQL MD5 (salted)
    "postgresql_md5": {
        "length": 35,
        "characters": r"^md5[a-f0-9]{32}$",
        "example": "md5f5eebc1559e8c5e6d58c5f7c5d9a6547"
    },

    # Apache htpasswd MD5 (APR1)
    "apache_md5": {
        "length": 37,
        "characters": r"^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$",
        "example": "$apr1$abc$X.xJ8/xQR3gwe60"
    },

    # Joomla Bcrypt Hash
    "joomla_bcrypt": {
        "length": 60,
        "characters": r"^\$2y\$[a-zA-Z0-9./]{56}$",
        "example": "$2y$10$eImiTXuWVxfM37uY4JANjQ=="
    },

    # HMAC-SHA1
    "hmac_sha1": {
        "length": 40,
        "characters": r"^[a-f0-9]{40}$",
        "example": "b617318655057264e28bc0b6fb378c8ef146be00"
    },

    # HMAC-SHA256
    "hmac_sha256": {
        "length": 64,
        "characters": r"^[a-f0-9]{64}$",
        "example": "f7bc83f430538424b13298e6aa6fb143ef4d59a149461b44f842d3c3d209ba27"
    },

    # HMAC-SHA512
    "hmac_sha512": {
        "length": 128,
        "characters": r"^[a-f0-9]{128}$",
        "example": "b0ba465637458c6990e5a8c5f61d4f42e5252dff2e8b6f798b9e8e6d8a5e4c07aaf0b9375ab62333a0d8d07e87f4a2b3"
    },

    # Ethereum Keccak-256 Hash (e.g., used for Ethereum wallet addresses)
    "keccak_eth": {
        "length": 64,
        "characters": r"^[a-f0-9]{64}$",
        "example": "c6d7e1b8e6d9b4b333c3a9e4ff8e5fafe6f0f1d08c9b7c6d6e7d1e2f3e4f5g6h"
    },

    # Base64 Encoded SHA-256
    "base64_sha256": {
        "length": 44,
        "characters": r"^[A-Za-z0-9+/]{43}=$",
        "example": "u0fKmF3F1VJQFHpbhdeyP3x4XFAHtZ7cloeEXb8tHV4="
    },

    # SHA-1 with Base64 encoding
    "base64_sha1": {
        "length": 28,
        "characters": r"^[A-Za-z0-9+/]{27}=$",
        "example": "Lve95gjOVATpfV8EL5X4nxwjKHE="
    },

    # SHA-256 with Base64 encoding
    "base64_sha256": {
        "length": 44,
        "characters": r"^[A-Za-z0-9+/]{43}=$",
        "example": "u6f+ZJQCM6+/5c9bDJgQOnJ38bLkN8+gHtMf+OHHrO4="
    },

    # Git Commit Hash (SHA-1)
    "git_commit_sha1": {
        "length": 40,
        "characters": r"^[a-f0-9]{40}$",
        "example": "d6b90e6f0cd1b7abbd0af12f1596d3f5e204ed73"
    },

    # LM Hash (used by legacy Windows systems for LAN Manager)
    "lm_hash": {
        "length": 32,
        "characters": r"^[A-F0-9]{32}$",
        "example": "E52CAC67419A9A224A3B108F3FA6CB6D"
    },

    # Oracle 12c (PBKDF2 with SHA-512)
    "oracle12c_pbkdf2_sha512": {
        "length": 128,
        "characters": r"^[a-f0-9]{128}$",
        "example": "A27D434B8741E9B4C6D4E47EDE2A60C7089DBBB77F65A49E9AE17F63DE8E6FF9"
    },

    # IPFS (InterPlanetary File System) Hashes
    "ipfs_hash": {
        "length": 46,
        "characters": r"^Qm[a-zA-Z0-9]{44}$",
        "example": "QmYwAPJzv5CZsnAzt8auVTLk9shP9bp1CuM3XKHu1QLH9E"
    },

    # bcrypt_sha256
    "bcrypt_sha256": {
        "length": 60,
        "characters": r"^\$2b\$[0-9]{2}\$[A-Za-z0-9./]{53}$",
        "example": "$2b$12$eXfJ0sjlW.DIcD6o4.mR9e/WCZDL.JEx8Bd2h6AWz3mWoLXXlU1Gm"
    },

    # Base58 Encoded (used by Bitcoin addresses)
    "base58_encoded": {
        "length": 34,
        "characters": r"^[1-9A-HJ-NP-Za-km-z]{34}$",
        "example": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    },

    # PBKDF2-HMAC-SHA1 (Generic)
    "pbkdf2_hmac_sha1": {
        "length": 40,
        "characters": r"^[a-f0-9]{40}$",
        "example": "9c69b3d1b1144c4e764b1f747d4e3a91bfa0f35b"
    },

    # PBKDF2-HMAC-SHA256 (Generic)
    "pbkdf2_hmac_sha256": {
        "length": 64,
        "characters": r"^[a-f0-9]{64}$",
        "example": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    },

    # PBKDF2-HMAC-SHA512 (Generic)
    "pbkdf2_hmac_sha512": {
        "length": 128,
        "characters": r"^[a-f0-9]{128}$",
        "example": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" \
                    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    }
}


