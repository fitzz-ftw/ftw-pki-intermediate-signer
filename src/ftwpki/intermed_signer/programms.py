# File: src/ftwpki/intermed_signer/programms.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
programms
===============================

Main entry points for Intermediate CA operations. (rw)
"""

import getpass
import traceback
from pathlib import Path

from cryptography import x509

from ftwpki.baselibs.cli_parser import CSRMultiSigningParser
from ftwpki.baselibs.configuration import IntermedPKIConfig
from ftwpki.baselibs.core import (
    cert_to_record,
    get_subject_dict,
    load_certificate_from_pem,
    load_csr_from_pem,
    load_private_key_from_pem,
)
from ftwpki.baselibs.openssl_comp import DbOpensslFile
from ftwpki.baselibs.package import PKIPackage
from ftwpki.baselibs.passwd import PasswordManager
from ftwpki.baselibs.policies import (
    ClientPolicy,
    ClientServerPolicy,
    IntermediatePolicy,
    ServerPolicy,
    UserPolicy,
)
from ftwpki.baselibs.signer import CertificateSigner
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
        pre_parser = CSRMultiSigningParser(add_help=False, allow_abbrev=False)
        pre_args, _ = pre_parser.parse_known_args(argv)
        cert_name = pre_args.certificate.split(".")
        pre_args.certificat = (
        pre_args.certificate if len(cert_name) >= 3 else f"{cert_name[0]}.crt.pem"
        )
        cert_name = cert_name[0]
        if cert_name:
            config = IntermedPKIConfig(cert_name)
            config.handle_pki_file()

        ca_parser = CSRMultiSigningParser()
        file_conf = (config.get_dn_policies(f"{cert_name}.policy", pre_args.policy_name) 
                     if cert_name else {})
        ca_parser.set_defaults(**file_conf)
        args = ca_parser.parse_args(argv)
        extention = config.get_extentions(f"{cert_name}.policy", pre_args.policy_name)
        # !SECTION - Configuration

        # SECTION - Validating
        current_path_length = config.own_cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.path_length
        if (args.policy_name == "intermediate" 
                and current_path_length 
                and current_path_length <= args.path_length
            ):
            print(f"Path length too high: {current_path_length}")
            return 1

        csr = load_csr_from_pem(Path(args.certificat_sign_request).read_bytes())

        val_dn = ValidatorDN(args.policy, get_subject_dict(config.own_cert))
        validate_result = val_dn.validate(get_subject_dict(csr))
        validate_result.errors.sort()

        # !SECTION - Validating

        # SECTION - Passwordhandling
        pwd_man = PasswordManager(private_dir=str(config.private_keys))
        pass_phrase = pwd_man.decrypt_password_file(
            str(config.private_keys / args.passphrasefile), 
            getpass.getpass("Enter Password:")
        )
        # !SECTION - Passwordhandling

        # SECTION - Signing
        private_key_obj = load_private_key_from_pem(
            pem_data=config.private_key(), 
            passphrase=pass_phrase
        )
        cert_signer = CertificateSigner(ca_cert=config.own_cert, ca_key=private_key_obj)
        policy_select = {
            "intermediate": IntermediatePolicy(path_length=args.path_length),
            "standalone": ClientServerPolicy(),
            "user": UserPolicy(),
            "client": ClientPolicy(),
            "server": ServerPolicy(),
        }
        policy = policy_select[args.policy_type]
        validity_days = validate_and_clamp_validity(config.own_cert, args.validity_days)

        signed_cert = cert_signer.sign(
            csr=csr, 
            policy=policy, 
            validity_days=validity_days.actual_days, 
            **extention
        )
        signed_pem = cert_signer.get_pem(signed_cert)
        # !SECTION - Signing

        # SECTION - Transferfile
        out_package = PKIPackage()
        out_package.recipient_cert = signed_cert
        out_package.private_key = private_key_obj
        out_package.caroot_cert = config.own_cert
        out_package.ca_cert = config.own_cert
        out_package.fullchain.extend(config.fullchain)
        out_package.to_encrypt = True
        out_package.save(args.certificat_sign_request)
        # !SECTION - Transferfile

        # SECTION - Database openssl compatible
        db_dir = Path("db")
        if not db_dir.is_dir():
            db_dir.mkdir(parents= True)
        db_file= DbOpensslFile(db_dir/"index.txt")
        db_file.add_record(record=cert_to_record(
            cert = load_certificate_from_pem(signed_pem),
            status = "V")
            )
        #!SECTION - Database openssl compatible


        return 0
    except KeyboardInterrupt:
        return 1
    except Exception as e:
        traceback.print_exc()
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
    passed_files = 0

    # Pfad zu den dokumentierenden Tests
    testfiles_dir = Path(__file__).parents[3] / "doc/source/devel"
    test_files = [
        "get_started_programms.rst",
        "get_started_run_programms.rst",
        ]

    for file in test_files:
        test_file = testfiles_dir / file
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
            if doctestresult.failed > 0 and option_flags & FAIL_FAST:
                print(f"Doctest result for {test_file.name}: {doctestresult}")
                print(
                    f"\nKeep going! You already passed {passed_files} files "
                    f"with {test_sum} tests before this hit."
                )
                break  # Stop on first failure if FAIL_FAST is set
            passed_files += 1
        else:
            print(f"⚠️ Warning: Test file {test_file.name} not found.")
    if test_failed == 0:
        print(f"\nDocTests passed without errors, {test_sum} tests.")
    else:
        if not option_flags & FAIL_FAST:
            print(f"\nDocTests failed: {test_failed} tests out of {test_sum}.")
