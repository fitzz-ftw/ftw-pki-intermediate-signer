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



>>> rel_data = Path("test_ok_data")
>>> _ = env.copy2config(rel_data /"M-V-HH-CA.pki",
...            config.passphrases/"M-V-HH-CA.pki")
>>> _ = env.copy2config(rel_data / "inter1secret",
...             config.passphrases/"inter1secret")
>>> _ = env.copy2cwd(rel_data / "member_server.csr",
...            "member_server.csr")

>>> del config


.. !SECTION
.. SECTION - Prepare

>>> from pathlib import Path


>>> def stub_getpass(prompt:str)->str:
...     print(prompt)
...     return "secret"

>>> def stub_keyboard_interrupt(prompt:str)->str:
...     print(prompt)
...     raise KeyboardInterrupt 

>>> def stub_exception(prompt:str)->str:
...     raise Exception("This is a testexception.")


>>> import getpass 
>>> getpass.getpass = stub_getpass



>>> cmd_line = " -k intermed1 "
>>> cmd_line += " --policy-name standalone "
>>> cmd_line += " -t server"
>>> cmd_line += " -c M-V-HH-CA.crt.pem"
>>> cmd_line += " inter1secret"
>>> cmd_line += " member_server.csr"

>>> import shlex
>>> sys_argv= shlex.split(cmd_line) 
>>> sys_argv #doctest: +NORMALIZE_WHITESPACE
['-k', 'intermed1', 
 '--policy-name', 'standalone', 
 '-t', 'server', 
 '-c', 'M-V-HH-CA.crt.pem', 
 'inter1secret', 
 'member_server.csr']

.. !SECTION - Prepare

>>> from ftwpki.intermed_signer.programms import prog_intermediate_sign

>>> prog_intermediate_sign(sys_argv)
Enter Password:
0

>>> _ = env.copy2cwd(rel_data / "member_server.csr",
...            "member_server.csr")
>>> getpass.getpass = stub_keyboard_interrupt
>>> prog_intermediate_sign(sys_argv)
Enter Password:
1


>>> _ = env.copy2cwd(rel_data / "member_server.csr",
...            "member_server.csr")
>>> getpass.getpass = stub_exception
>>> prog_intermediate_sign(sys_argv)
This is a testexception.
1

.. SECTION To high path_length

>>> cmd_line = " -k intermed1 "
>>> cmd_line += " --policy-name standalone "
>>> cmd_line += " --path-length 99 "
>>> cmd_line += " -t server"
>>> cmd_line += " -c M-V-HH-CA.crt.pem"
>>> cmd_line += " inter1secret"
>>> cmd_line += " member_server.csr"

>>> sys_argv= shlex.split(cmd_line) 
>>> getpass.getpass = stub_getpass

Keinen einfluss, da kein intermediate csr.

>>> prog_intermediate_sign(sys_argv)
Enter Password:
0


>>> cmd_line = " -k intermed1 "
>>> cmd_line += " --policy-name standalone "
>>> cmd_line += " --path-length 99 "
>>> cmd_line += " -t intermediate"
>>> cmd_line += " -c M-V-HH-CA.crt.pem"
>>> cmd_line += " inter1secret"
>>> cmd_line += " member_server.csr"

>>> sys_argv= shlex.split(cmd_line) 
>>> getpass.getpass = stub_getpass

>>> prog_intermediate_sign(sys_argv) #doctest: +SKIP


.. ANCHOR - Testen auf policymissmage
>>> cmd_line = " -k intermed1 "
>>> cmd_line += " -C no "
>>> cmd_line += " -O no "
>>> cmd_line += " --policy-name standalone "
>>> cmd_line += " -t server"
>>> cmd_line += " -c M-V-HH-CA.crt.pem"
>>> cmd_line += " inter1secret"
>>> cmd_line += " member_server.csr"
>>> sys_argv= shlex.split(cmd_line) 

>>> _ = env.copy2cwd(rel_data / "member_server.csr",
...            "member_server.csr")
>>> getpass.getpass = stub_getpass
>>> prog_intermediate_sign(sys_argv)
While policyvalidation following missmatch occurs:
    - [countryName]: DISALLOWED
    - [organizationName]: DISALLOWED
1

.. SECTION - Teardown

>>> env.clean_home()
>>> env.teardown()

.. !SECTION
