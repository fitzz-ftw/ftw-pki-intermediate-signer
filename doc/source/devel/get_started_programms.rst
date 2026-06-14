The Signing Intermediate Programm
####################################

.. SECTION - Setup
>>> appname="ftwpki"
>>> appauthor= "FitzzTechXikWelt"

>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"),
...     appname=appname, appauthor=appauthor
...     )
>>> env.setup(True)
>>> env.clean_output()

>>> from ftwpki.baselibs.configuration import IntermedPKIConfig
>>> config:IntermedPKIConfig = IntermedPKIConfig()



>>> rel_data = Path("data-inter-base-signer")
>>> _ = env.copy2config(rel_data /"unpacked/M-V-HH-CA.pki",
...            config.passphrases/"M-V-HH-CA.pki")
>>> _ = env.copy2config(rel_data / "inter1secret",
...             config.passphrases/"inter1secret")
>>> _ = env.copy2cwd(rel_data / "M-V-HH-Infra-CA.csr",
...            "M-V-HH-Infra-CA.csr")

>>> del config


.. !SECTION
.. SECTION - Prepare

>>> from pathlib import Path


>>> def getpasswd(prompt:str)->str:
...     print(prompt)
...     return "secret"


>> cmd_line =  "--conf-file ca_intermed_hamburg_conf.toml"

>>> cmd_line = " -k intermed1 "
>>> cmd_line += " --policy-name standalone "
>>> cmd_line += " -t server"
>>> cmd_line += " -c M-V-HH-CA.crt.pem"
>>> cmd_line += " inter1secret"
>>> cmd_line += " M-V-HH-Infra-CA.csr"

>>> import shlex
>>> sys_argv= shlex.split(cmd_line) 
>>> sys_argv #doctest: +NORMALIZE_WHITESPACE
['-k', 'intermed1', 
 '--policy-name', 'standalone', 
 '-t', 'server', 
 '-c', 'M-V-HH-CA.crt.pem', 
 'inter1secret', 
 'M-V-HH-Infra-CA.csr']

.. !SECTION - Prepare


.. SECTION - Programm Signing

.. SECTION - Configuration
>>> from ftwpki.baselibs.configuration import IntermedPKIConfig


>>> from ftwpki.baselibs.toml_utils import toml2dn_policy, toml2ext
>>> from ftwpki.baselibs.cli_parser import CSRMultiSigningParser

>>> pre_parser = CSRMultiSigningParser(add_help=False, allow_abbrev=False)
>>> pre_args , _ = pre_parser.parse_known_args(sys_argv)

>>> cert_name = pre_args.certificate.split(".")


>>> pre_args.certificat = pre_args.certificate if len(cert_name) >= 3 else f"{cert_name[0]}.crt.pem"  

>>> cert_name = cert_name[0]


>>> config = IntermedPKIConfig(cert_name)
>>> config.handle_pki_file()


>>> ca_parser = CSRMultiSigningParser()

>>> file_conf = config.get_dn_policies(f"{cert_name}.policy",pre_args.policy_name)


>>> ca_parser.set_defaults(**file_conf)


>>> extention = config.get_extentions(f"{cert_name}.policy", pre_args.policy_name)



>>> args = ca_parser.parse_args(sys_argv)
>>> args #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS 
Namespace(countryName='match', 
     stateOrProvinceName='optional', 
     localityName='match', 
     organizationName='match', 
     organizationalUnitName='optional', 
     commonName='supplied', 
     policy_name='standalone', 
     conf_file=None, 
     key_name='intermed1', 
     private_dir=None, 
     certificate='M-V-HH-CA.crt.pem', 
     validity_days=365, 
     path_length=0, 
     passphrasefile='inter1secret', 
     certificat_sign_request='M-V-HH-Infra-CA.csr', 
     policy_type='server', 
     policy={'countryName': 'match', 
          'stateOrProvinceName': 'optional', 
          'localityName': 'match', 
          'organizationName': 'match', 
          'organizationalUnitName': 'optional', 
          'commonName': 'supplied'}, 
     private_key='intermed1.key.pem')



.. !SECTION - Configuration

.. SECTION - Validating

>>> from ftwpki.baselibs.core import (
...     load_certificate_from_pem, 
...     load_csr_from_pem,
...     get_subject_dict,
...     )




>>> from cryptography import x509

>>> current_path_length = config.own_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length

>>> current_path_length
1



>>> if (args.policy_name == "intermediate" 
...     and current_path_length <= args.path_length):
...     print("!!!Programstop!!!")
...     print("Returncode: 1")

>>> csr = load_csr_from_pem(Path(args.certificat_sign_request).read_bytes())




>>> from ftwpki.baselibs.validate import ValidatorDN

>>> val_dn= ValidatorDN(args.policy,
...          get_subject_dict(config.own_cert))
>>> validate_result=val_dn.validate(get_subject_dict(csr))
>>> validate_result.errors.sort()

Validierung der DN-Policy
---------------------------
Bevor der eigentliche Signiervorgang startet, wird der CSR gegen 
die in der Konfiguration (intermed_conf.toml) definierte Policy 
geprüft.

Im obigen Beispiel ist die Policy für stateOrProvinceName auf 
supplied gesetzt. Da der vorliegende CSR dieses Feld jedoch nicht 
enthält, erkennt der ValidatorDN die Diskrepanz:

Ergebnis: validate_result.is_valid ist False.

Fehlermeldung: [stateOrProvinceName]: SUPPLIED signalisiert das 
fehlende Pflichtfeld.

Wichtig: In einer produktiven Umgebung führt dieser 
Validierungsfehler dazu, dass das Programm sofort mit dem 
Returncode 1 abbricht. Es wird kein Zertifikat ausgestellt, 
das nicht den Richtlinien entspricht. Dies stellt die Konsistenz 
der gesamten Zertifikatskette sicher.

Returncode: 1

.. !SECTION - Validating


.. SECTION - Passwordhandling

>>> from ftwpki.baselibs.passwd import PasswordManager
>>> pwd_man = PasswordManager(str(config.private_keys))
>>> pwd_man #doctest: +ELLIPSIS
PasswordManager(private_dir='.../ftwpki/.private')

>>> config.private_keys.as_posix() #doctest: +ELLIPSIS 
'...ftwpki/.private'

>>> pass_phrase = pwd_man.decrypt_password_file(
...         config.private_keys/args.passphrasefile, 
...         getpasswd("Enter Password:"))
Enter Password:

.. !SECTION - Passwordhandling



.. SECTION - Signing


>>> from ftwpki.baselibs.core import (
...     load_private_key_from_pem,
...     load_csr_from_pem,
...     save_pem,
...     cert_to_record,
...     )
>>> from ftwpki.baselibs.signer import CertificateSigner





>>> private_key_obj= load_private_key_from_pem(
...     pem_data = config.private_key(), 
...     passphrase=pass_phrase)

>> type(private_key_obj)

>>> cert_signer = CertificateSigner(
...      ca_cert=config.own_cert,
...      ca_key=private_key_obj)



>>> from ftwpki.baselibs.policies import IntermediatePolicy

>>> from ftwpki.baselibs.policies import ClientServerPolicy

>>> from ftwpki.baselibs.policies import UserPolicy

>>> from ftwpki.baselibs.policies import ClientPolicy

>>> from ftwpki.baselibs.policies import ServerPolicy

>>> policy_select = {
...       "intermediate": IntermediatePolicy(path_length = args.path_length),
...       "standalone": ClientServerPolicy(),
...       "user": UserPolicy(),
...       "client": ClientPolicy(),
...       "server": ServerPolicy(),
...       }

>>> policy = policy_select[args.policy_type]

>>> policy
ServerPolicy()

IntermediatePolicy(path_length: 0)



>>> from ftwpki.baselibs.validate import validate_and_clamp_validity

>>> validity_days= validate_and_clamp_validity(config.own_cert, args.validity_days)

>>> signed_cert = cert_signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=validity_days.actual_days,
...     **extention)

>>> signed_cert # doctest: +ELLIPSIS
<Certificate(subject=<Name(...)>, ...)>


..NOTE - Testcase for checking only

>>> signed_pem = cert_signer.get_pem(signed_cert)
>>> target_path = Path(args.certificat_sign_request).with_suffix(".crt.pem")
>>> save_pem(data = signed_pem, 
...     target_path=target_path, 
...     is_private = True)

.. !SECTION - Signing
.. SECTION - load certs for chain

.. !SECTION - load certs for chain


.. SECTION - Transferfile



>>> from ftwpki.baselibs.package import PKIPackage

>>> out_package = PKIPackage()
>>> out_package.recipient_cert = signed_cert
>>> out_package.private_key = private_key_obj
>>> out_package.caroot_cert = config.own_cert

>>> out_package.ca_cert = config.own_cert

>>> out_package.fullchain.extend(config.fullchain)

>>> out_package.fullchain #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
[<Certificate(subject=<Name(...CN=Muster-Verband Bundesverband Root CA...)>, ...)>, 
 <Certificate(subject=<Name(...CN=Muster-Verband Bundesverband Root CA...)>, ...)>]

>>> out_package.to_encrypt=True

False

>>> transfer_file_path = out_package.save(args.certificat_sign_request)

>>> transfer_file_path.as_posix()
'M-V-HH-Infra-CA.spki'


.. !SECTION - Transferfile



.. SECTION - Testing only

>>> with transfer_file_path.open("rb") as f:
...     f.readline()
...     f.readline()
...     f.readline()
...     f.readline()
b'MIME-Version: 1.0\n'
b'Content-Disposition: attachment; filename="smime.p7m"\n'
b'Content-Type: application/pkcs7-mime; smime-type="enveloped-data"; name="smime.p7m"\n'
b'Content-Transfer-Encoding: base64\n'

.. !SECTION



.. SECTION - Database openssl compatible

>>> from ftwpki.baselibs.openssl_comp import DbOpensslFile
>>> db_dir = Path("db")
>>> if not db_dir.is_dir():
...     db_dir.mkdir(parents= True)

>>> db_file= DbOpensslFile(db_dir/"index.txt")
>>> db_file.add_record(record=cert_to_record(
...     cert = load_certificate_from_pem(signed_pem),
...     status = "V")
...     )


.. !SECTION - Database openssl compatible


.. !SECTION - Programm Signing

.. SECTION - Check Result 

>>> from ftwpki.baselibs.utils import get_cert_text

>>> print(get_cert_text(target_path.as_posix())) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Subject:
     CN=Muster-Verband Hamburg Systems Issuing CA...
Issuer:
     CN=Muster-Verband Hamburg Regional CA...
Serial Number:
     ...
Not Before:
     20...
Not After:
     20...
Version:
     v3
Extensions:
     basicConstraints:
          CA=No, path_length=None
     keyUsage:
          digital_signature, key_encipherment
     extendedKeyUsage:
          serverAuth
     authorityKeyIdentifier:
          b...
     authorityInfoAccess:
          OCSP: http://ocsp.example.org/ham
          caIssuers: http://pki.example.org/root/root.crt
     cRLDistributionPoints:
          http://pki.example.org/ham/regional.crl
     subjectKeyIdentifier:
          b...






.. !SECTION - Check Result 


.. SECTION - Teardown

>>> env.clean_home()
>>> env.teardown()

.. !SECTION
