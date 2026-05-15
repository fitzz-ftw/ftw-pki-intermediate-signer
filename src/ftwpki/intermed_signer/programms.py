# File: src/ftwpki/intermed/programms.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
programms
===============================

Main entry points for Intermediate CA operations. (rw)
"""

import getpass
from pathlib import Path

from cryptography import x509

from ftwpki.baselibs.cli_parser import CSRMultiSigningParser, cast
from ftwpki.baselibs.core import (
    get_subject_dict,
    load_certificate_from_pem,
    load_csr_from_pem,
    load_private_key_from_pem,
)
from ftwpki.baselibs.passwd import PasswordManager
from ftwpki.baselibs.policies import (
    ClientPolicy,
    ClientServerPolicy,
    IntermediatePolicy,
    ServerPolicy,
    UserPolicy,
)
from ftwpki.baselibs.signer import CertificateSigner
from ftwpki.baselibs.toml_utils import (
    toml2dn_policy,
    toml2ext_policy,
)
from ftwpki.baselibs.transport import encrypt_transport_package
from ftwpki.baselibs.validate import ValidatorDN, validate_and_clamp_validity

# SECTION - Programm Signing


def prog_intermediate_sign(argv: list[str] | None = None, **kwargs) -> int:
    """
    Entry point for signing requests using an Intermediate CA. (rw)

    :param argv: Optional list of command-line arguments.
    :param kwargs: Additional signing options.
    :returns: Exit code (0 for success, 1 for error).
    """
    try:
        # SECTION - Configuration
        ca_parser = CSRMultiSigningParser()
        ca_parser.set_defaults(**toml2dn_policy(argv))
        extention = toml2ext_policy(argv)
        args = ca_parser.parse_args(argv)
        # !SECTION - Configuration

        # SECTION - Validating
        ca_cert = load_certificate_from_pem(pem_data=Path(args.certificate).read_bytes())
        current_path_length = cast(
            int, ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
        )
        if args.policy_name == "intermediate" and current_path_length <= args.path_length:
            print(f"Path length too high: {current_path_length}")
            return 1

        csr = load_csr_from_pem(Path(args.certificat_sign_request).read_bytes())
        val_dn = ValidatorDN(args.policy, get_subject_dict(ca_cert))
        validate_result = val_dn.validate(get_subject_dict(csr))
        validate_result.errors.sort()

        if not validate_result.is_valid:
            for error in validate_result.errors:
                print(error)
            return 1
        # !SECTION - Validating

        # SECTION - Passwordhandling
        pwd_man = PasswordManager(private_dir=args.private_dir)
        pass_phrase = pwd_man.decrypt_password_file(
            args.passphrasefile, getpass.getpass("Enter Password:")
        )
        # !SECTION - Passwordhandling

        # SECTION - Signing
        private_key_obj = load_private_key_from_pem(
            pem_data=Path(args.private_key).read_bytes(), passphrase=pass_phrase
        )
        cert_signer = CertificateSigner(ca_cert=ca_cert, ca_key=private_key_obj)
        policy_select = {
            "intermediate": IntermediatePolicy(pathlength=args.path_length),
            "standalone": ClientServerPolicy(),
            "user": UserPolicy(),
            "client": ClientPolicy(),
            "server": ServerPolicy(),
        }
        policy = policy_select[args.policy_type]
        validity_days = validate_and_clamp_validity(ca_cert, args.validity_days)

        signed_cert = cert_signer.sign(
            csr=csr, policy=policy, validity_days=validity_days.actual_days, **extention
        )
        # !SECTION - Signing

        # SECTION - Transferfile
        zipped_data = encrypt_transport_package(
            signed_cert,  # user_cert
            ca_cert,  # root_ca_cert
            private_key_obj,
            signed_cert,  # recipient_cert
            signed_cert,
            ca_cert,
        )
        transfer_file_path = Path(args.certificat_sign_request).with_suffix(".zip.enc")
        transfer_file_path.write_bytes(zipped_data)
        # !SECTION - Transferfile

        return 0
    except KeyboardInterrupt:
        return 1
    except Exception as e:
        print(e)
        return 1


# !SECTION - Programm Signing


if __name__ == "__main__":  # pragma: no cover
    from doctest import FAIL_FAST, testfile

    be_verbose = False
    be_verbose = True
    option_flags = 0
    option_flags = FAIL_FAST
    test_sum = 0
    test_failed = 0

    # Pfad zu den dokumentierenden Tests
    testfiles_dir = Path(__file__).parents[3] / "doc/source/devel"
    test_file = testfiles_dir / "get_started_programms.rst"
    # test_file = testfiles_dir / "get_started_prog_intermed_sign.rst"

    if test_file.exists():
        print(f"--- Running Doctest for {test_file.name} ---")
        doctestresult = testfile(
            str(test_file),
            module_relative=False,
            verbose=be_verbose,
            optionflags=option_flags,
        )
        test_failed += doctestresult.failed
        test_sum += doctestresult.attempted
        if test_failed == 0:
            print(f"\nDocTests passed without errors, {test_sum} tests.")
        else:
            print(f"\nDocTests failed: {test_failed} tests.")
    else:
        print(f"⚠️ Warning: Test file {test_file.name} not found.")
