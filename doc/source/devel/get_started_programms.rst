The Signing Intermediate Programm
####################################

.. SECTION - Setup

>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)
>>> conf_file = env.copy2cwd("intermed_conf.toml")

.. !SECTION
.. SECTION - Prepare

>>> from pathlib import Path
>>> private_dir:Path = Path("privat")
>>> private_dir.mkdir(parents=True, exist_ok=True)
>>> test_paswd_path = env.copy2cwd("privat/testpasswd")
>>> ca_key_path = env.copy2cwd("privat/reinsha.key.pem")

>>> ca_cert_path = env.copy2cwd("reinsha_public/Fitzz-TeXnik-WeltSomewherecity.crt", 
...       "Fitzz-TeXnik-WeltSomewherecity.crt")
>>> ca_cert_path = env.copy2cwd("reinsha_public/reinsha.pub.pem", "reinsha.pub.pem")
>>> ca_cert_path = env.copy2cwd("cert_in/node-01.csr","node-01.csr")

>>> def getpasswd(prompt:str)->str:
...     print(prompt)
...     return "strenggeheim"


>>> cmd_line =  "--conf-file intermed_conf.toml"
>>> cmd_line += " -k privat/reinsha.key.pem "
>>> cmd_line += " --private-dir privat"
>>> cmd_line += " --policy-name standalone"
>>> cmd_line += " -t standalone"
>>> cmd_line += " -c Fitzz-TeXnik-WeltSomewherecity.crt"
>>> cmd_line += " testpasswd"
>>> cmd_line += " node-01.csr"

>>> import shlex
>>> sys_argv= shlex.split(cmd_line) 
>>> sys_argv #doctest: +NORMALIZE_WHITESPACE
['--conf-file', 'intermed_conf.toml', 
 '-k', 'privat/reinsha.key.pem', 
 '--private-dir', 'privat', 
 '--policy-name', 'standalone',
 '-t', 'standalone',
 '-c', 'Fitzz-TeXnik-WeltSomewherecity.crt',
 'testpasswd',
 'node-01.csr']

.. !SECTION



.. SECTION - Programm Signing

.. SECTION - Configuration

>>> from ftwpki.baselibs.toml_utils import toml2dn_policy, toml2ext_policy
>>> from ftwpki.baselibs.cli_parser import CSRMultiSigningParser

>>> ca_parser = CSRMultiSigningParser(prog="ftwpkicasign")

>>> ca_parser.set_defaults(**toml2dn_policy(sys_argv))
>>> extention = toml2ext_policy(sys_argv)

>>> args = ca_parser.parse_args(sys_argv)
>>> args #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS 
Namespace(countryName='match', 
    stateOrProvinceName='supplied', 
    localityName='optional', 
    organizationName='match', 
    organizationalUnitName='optional', 
    commonName='supplied', 
    policy_name='standalone',
    conf_file=...Path('intermed_conf.toml'), 
    private_key='privat/reinsha.key.pem', 
    private_dir='privat',
    certificate='Fitzz-TeXnik-WeltSomewherecity.crt',
    validity_days=365,
    path_length=0, 
    passphrasefile='testpasswd',
    certificat_sign_request='node-01.csr',
    policy_type='standalone', 
    policy={'countryName': 'match', 
        'stateOrProvinceName': 'supplied', 
        'localityName': 'optional', 
        'organizationName': 'match', 
        'organizationalUnitName': 'optional', 
        'commonName': 'supplied'})


.. !SECTION

.. SECTION - Validating

>>> from ftwpki.baselibs.core import (
...     load_certificate_from_pem, 
...     load_csr_from_pem,
...     get_subject_dict,
...     )

>>> ca_cert = load_certificate_from_pem(
...      pem_data=Path(args.certificate).read_bytes())

>>> from cryptography import x509

>>> current_path_length = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length

>>> if (args.policy_name == "intermediate" 
...     and current_path_length <= args.path_length):
...     print("!!!Programstop!!!")
...     print("Returncode: 1")

>>> csr = load_csr_from_pem(Path(args.certificat_sign_request).read_bytes())




>>> from ftwpki.baselibs.validate import ValidatorDN

>>> val_dn= ValidatorDN(args.policy,
...          get_subject_dict(ca_cert))
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

>>> if not validate_result.is_valid:
...     for error in validate_result.errors:
...         print(error)
...     print("!!!Programstop!!!")
...     print("Returncode: 1")
  - [stateOrProvinceName]: SUPPLIED
!!!Programstop!!!
Returncode: 1

.. !SECTION - Validating



.. SECTION - Passwordhandling

>>> from ftwpki.baselibs.passwd import PasswordManager
>>> pwd_man = PasswordManager(private_dir=args.private_dir)
>>> pwd_man
PasswordManager(private_dir='privat')



>>> pass_phrase = pwd_man.decrypt_password_file(args.passphrasefile, getpasswd("Enter Password:"))
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
...             pem_data = Path(args.private_key).read_bytes(), 
...             passphrase=pass_phrase)


>>> cert_signer = CertificateSigner(
...      ca_cert=ca_cert,
...      ca_key=private_key_obj)



>>> from ftwpki.baselibs.policies import IntermediatePolicy

>>> from ftwpki.baselibs.policies import ClientServerPolicy

>>> from ftwpki.baselibs.policies import UserPolicy

>>> from ftwpki.baselibs.policies import ClientPolicy

>>> from ftwpki.baselibs.policies import ServerPolicy

>>> policy_select = {
...       "intermediate": IntermediatePolicy(pathlength = args.path_length),
...       "standalone": ClientServerPolicy(),
...       "user": UserPolicy(),
...       "client": ClientPolicy(),
...       "server": ServerPolicy(),
...       }

>>> policy = policy_select[args.policy_type]

>>> policy
ClientServerPolicy()




>>> from ftwpki.baselibs.validate import validate_and_clamp_validity

>>> validity_days= validate_and_clamp_validity(ca_cert, args.validity_days)

>>> signed_cert = cert_signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=validity_days.actual_days,
...     **extention)

>>> signed_cert # doctest: +ELLIPSIS
<Certificate(subject=<Name(...)>, ...)>



>>> signed_pem = cert_signer.get_pem(signed_cert)
>>> target_path = Path(args.certificat_sign_request).with_suffix(".crt")
>>> save_pem(data = signed_pem, 
...     target_path=target_path, 
...     is_private = True)

.. !SECTION - Signing



.. SECTION - Transferfile

>>> from ftwpki.baselibs.transport import encrypt_transport_package
>>> zipped_data = encrypt_transport_package(
...     signed_cert, # user_cert
...     ca_cert, # root_ca_cert
...     private_key_obj,
...     signed_cert, # recipient_cert
...     signed_cert,
...     ca_cert,
...     )

>>> transfer_file_path = Path(args.certificat_sign_request).with_suffix(".zip.enc")
>>> _ = transfer_file_path.write_bytes(zipped_data)

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
     CN=node-01.internal,OU=,O=Fitzz TeXnik Welt,L=,ST=,C=DE
Issuer:
     CN=Fitzz Reinshagen,OU=Security,O=Fitzz TeXnik Welt,L=Somewherecity,ST=Mystate,C=DE
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
          serverAuth, clientAuth
     authorityKeyIdentifier:
          b'...'
     authorityInfoAccess:
          OCSP: http://ocsp.deine-pki.test
          caIssuers: http://pki.deine-pki.test/ca.crt
     cRLDistributionPoints:
          http://pki.deine-pki.test/crl
     subjectKeyIdentifier:
          b'...'

.. !SECTION - Check Result 


.. SECTION - Teardown

>>> env.clean_home()
>>> env.teardown()

.. !SECTION
