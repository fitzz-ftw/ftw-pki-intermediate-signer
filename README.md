# ftw-pki-intermediate-signer

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL_v2.1-blue.svg)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)
[![Coverage: 100%](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](#)

A dedicated component of the **ftw-pki** suite focusing on the lifecycle and management of Intermediate Certificate Authorities. This repository provides the `ftwpkiintermedcsr` executable.

## 🛠 Features

* **Intermediate CSR Management:** Specialized logic for generating and handling Certificate Signing Requests (CSR) for Intermediate CAs.
* **Domain-Specific Modules:** Contains internal modules tailored for intermediate-level validation and security profiles.
* **Enhanced Security:** Supports high-entropy passphrases (~50+ characters) by integrating with the `ftw-pki-password` utility.
* **Chain of Trust:** Facilitates the secure link between the Root CA and the issuing entities.

## 📖 Documentation & Usage

This tool is used to bridge the gap between the Root of Trust and operational issuing authorities.

* **Command Line Interface:** The `ftwpkiintermedcsr` utility provides specific commands for intermediate CA setup. Run `ftwpkiintermedcsr --help` for usage details.
* **Prerequisites:** Secure passphrase handling requires a pre-configured setup from `ftw-pki-password`.
* **Technical Manual:** Detailed documentation on the internal modules and intermediate-specific logic is available in the `doc/source/` directory.

## 📄 License

This project is licensed under the **LGPL v2.1 (or later)**.

---
© 2026 ftw-pki Contributors
