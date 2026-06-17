# Changelog: ftw-pki-intermed-signer

All notable changes to this project will be documented in this file.

## [0.0.4] - 2026-06-17

### Added
- Implement database record tracking for signing operations
- Add temporary DEV testing assets and test artifacts

### Changed
- Align intermediate signing tool with unified key-name schema
- Integrate TomlPreParser into intermediate CSR program
- Adapt to streamlined baselibs and modernize utility interfaces
- Rename legacy TOML functions to break search patterns
- Refactor signer logic and improve error handling protocols

### Fixed
- Improve error handling in ftwpki.intermed_signer

### Documentation
- Update technical documentation and clean up imports


## [0.0.3a2] - 2026-05-18

### Added
- Add automated GitHub Actions CI/CD pipeline configurations (`ci.yml`) for multi-environment validation.

### Changed
- Refactor internal exception handling structures and modernize configuration processing routines inside `ftwpkiintermedsign` entry points.

## [0.0.3a1] - 2026-05-15

### Added
- **Standalone Package**: First independent release dedicated strictly to intermediate signing operations.
- **Namespace Transition**: Migrated all modules to `ftwpki.intermed_signer`.
- **SCM Versioning**: Updated `tag_regex` in `pyproject.toml` to support alpha-release versioning schemes.

### Changed
- **Version Bump**: Promoted to 0.0.3a1 to clearly distinguish this standalone package from the previous combined releases.
- **CLI Entry Point**: Fixed `ftwpkiintermedsign` to point to the new `intermed_signer` namespace.

### Fixed
- **Documentation**: Cleaned up README and fixed broken links/MyST warnings.

## [0.0.2a1] - 2026-05-06
- **Pre-Split State**: Final version of the combined intermediate logic before separating into standalone packages.

## [0.0.2] - 2026-05-01
- **API Documentation**: Implemented PEP 257 and Sphinx-compliant docstrings.

## [0.0.1] - 2024-11-20
- **Initial Commit**: Basic implementation of the signing logic.
