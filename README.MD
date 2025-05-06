# Kuncy - Peruri ID Key Pair Generator

Kuncy is a Go-based utility designed for generating, signing, and encrypting cryptographic key pairs and managing JSON Web Key Sets (JWKS). This project aligns with the Peruri ID digital identity framework, offering support for ECDSA and EdDSA keys and utilizing modern cryptographic libraries.

---

## Features

- **Key Generation**: Generate secure ECDSA and EdDSA key pairs for signing and encryption.
- **Signing and Verification**: Create and verify signed JWTs with ES512 and EdDSA algorithms.
- **Encryption and Decryption**: Encrypt payloads using ECDH-ES with AES-256-KW and decrypt them using JWK key sets.
- **JWKS Management**: Automatically generate and export JSON Web Key Sets (JWKS) for use in secure applications.
- **Platform Compatibility**: Build and package the application for Linux, macOS, and Windows.

---

## Installation

### Download the Binary

You can download the prebuilt binary from the [GitHub Releases Page](https://github.com/peruri-dev/kuncy/releases).

#### Option 1: Using `curl`

For Linux:

```
curl -L -o kuncy.tar.gz https://github.com/peruri-dev/kuncy/releases/download/<version>/kuncy-<version>-linux.tar.gz
```

For macOS:

```
curl -L -o kuncy.tar.gz https://github.com/peruri-dev/kuncy/releases/download/<version>/kuncy-<version>-darwin.tar.gz
```

For Windows:

```
curl -L -o kuncy.zip https://github.com/peruri-dev/kuncy/releases/download/<version>/kuncy-<version>-windows.zip
```

#### Option 2: Using `wget`

For Linux:

```
wget -O kuncy.tar.gz https://github.com/peruri-dev/kuncy/releases/download/<version>/kuncy-<version>-linux.tar.gz
```

For macOS:

```
wget -O kuncy.tar.gz https://github.com/peruri-dev/kuncy/releases/download/<version>/kuncy-<version>-darwin.tar.gz
```

For Windows:

```
wget -O kuncy.zip https://github.com/peruri-dev/kuncy/releases/download/<version>/kuncy-<version>-windows.zip
```

#### Option 3: Manual Download

1. Visit the [GitHub Releases Page](https://github.com/peruri-dev/kuncy/releases).
2. Download the appropriate binary for your operating system.
3. Save it to your desired directory.

---

### Extract the Binary

For Linux and macOS (tar.gz files):

```
tar -xvzf kuncy.tar.gz
chmod +x kuncy
```

For Windows (zip files):

Use your preferred archive manager (e.g., WinRAR, 7-Zip) to extract the `kuncy.exe` file.

---

## Usage

Run the application to generate key pairs and manage JWKS:

```
./kuncy
```

By default, the application performs the following:

- Generates ECDSA and EdDSA key pairs.
- Tests signing and encryption functionalities.
- Exports the generated JWKS to `jwks.json`.

You can customize the behavior by modifying the source files if you build from source.

### example output
```
+++++++++++++++++++++++++++++++++++
Kuncy - PeruriID key pair generator
+++++++++++++++++++++++++++++++++++

+ test signing in JWT format: PASSED
+ + output: eyJhbGciOiJFUzUxMiIsImtpZCI6Ijg1QkY1ODM5MTQyOTdGQzFGNUUxN0E0NzJEMjI4RDY1RDVDQUExNUFCM0FCNzc5NzE1OUMwQTYyRDY1ODFFQzEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3NDY1MTY0MjksImlhdCI6MTc0NjUxNTUyOSwianRpIjoiOUY1M0U4QTcxRUNCQTMwMDZBMzQwRUQ0NzlDQzdGOUI4NUI1MzQ0MzFFQzFGMEM0QzVGMjQxMEExRjRCODRBMyIsInN1YiI6IlBSUklEOTlJRCIsInR5cGUiOiJhc3NlcnRpb24ifQ.ASjTGJ7WkKjLv4r7eL58TV84afMMhBb1G3goShxAQcrnBW6uw7P4CvcUZwEy-I2DSsjWSCQJ6h023_opcyW0HLELAGWfl5t0ztgPlHqlL1F0B3-z94F8Eg57cQCXN-MTrJUmk7F87Gc8KPKpFBGZNG4p2JxX4tIuA8jA-Kdyb-aWEOKX

+ test parsing signed JWT: PASSED
+ + output: map[exp:2025-05-06 07:27:09 +0000 UTC iat:2025-05-06 07:12:09 +0000 UTC jti:9F53E8A71ECBA3006A340ED479CC7F9B85B534431EC1F0C4C5F2410A1F4B84A3 sub:PRRID99ID type:assertion] err: <nil>

+ test encryption in JWT format: PASSED
+ + output: eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBVjZOYXAyZkpwdTdKNDV4ZlhkWDdITzByeTZXZHhpUWlzN0x0MDdaUXFLQlJKYXJkNmNwaXkyZDc0UXBqNTltTkwwOWtQbjZQdlZfa3p1cTFUQkpmdnhlIiwieSI6IkFNcGdqSFQ0YkUzMGFXYy14ZVg4RTI5V3lBdzE4am5Yd1VHa1R5SjZoUEJNWGlLeEtyUWpDRkpEeWtybGZqdVh2VXE2ZDJ5QXZ1TG1JLXlBVEsxX3JpdkYifSwia2lkIjoiREY0MDk4QzQ3RDUxRDcyMEUwMDI3NzMyNEI4MTY2QUM5RENDQTc4NDUyMjUzNThBQzU3OTJENDU2RUI2RkI5RCJ9.w6Nt_2myqYy2sCcDr_RXhTdTNQX1WSPBGL0eZdjV2z5Zjodx458zvg.C__1p-DljNc3B5jc.btD46Cu-Fs2a4RRJ-6V6z40kSuIPq-u4tQmBzd-GvoCVwCF-wjt-JB8-4--hqa-Yq-Mc3J38CsIvBm0VE_TomH_R.3673KK3N6We5vT_ObcRLNQ

+ test decrypt chipertex of JWE: PASSED
+ + output: {"string":"Fulan","nik":"1000200030004000","PeruriID":"PRRID99ID"} err: <nil>

+++++++++++++ EXIT +++++++++++++
```

### file generated
```
- enc_privkey.pem
- enc_pubkey.pem
- jwks.json
- signing_privkey.pem
- signing_pubkey.pem
```

The file `jwks.json` contains both of signing and encryption public key in JWKS format. And it should be registered in Peruri ID.

You have to keep the `enc_privkey.pem` and `signing_privkey.pem` securely. As the encryption privkey is used to decrypt the id_token payload. and signing privkey is to sign a jwt assertion for oidc exchange token.   

---

## Dependencies

- [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx): For working with JWTs, JWKs, and cryptographic operations.
- [google/uuid](https://github.com/google/uuid): UUID generation.

For a full list of dependencies, see [`go.mod`](go.mod).

---

## Contribution

Feel free to fork this repository and open a pull request to contribute. Ensure that all new features are well-documented and tested.

---

## License

This project is licensed under the Apache License 2.0. See the [`LICENSE`](LICENSE) file for more details.

---

## Contact

For inquiries or support, please contact **@ghiyastfarisi** or open an issue in this repository.
