The Signing Intermediate Programm
####################################

.. SECTION - Setup
>>> appname="ftwpki"
>>> appauthor= "FitzzTechXikWelt"

>>> import getpass

>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"),
...     appname=appname, appauthor=appauthor
...     )
>>> env.setup(False)
>>> env.clean_output()

>>> from ftwpki.baselibs.configuration import IntermedPKIConfig
>>> config = IntermedPKIConfig()

>>> rel_private = config.private_keys.relative_to(env.config_dir)

>>> rel_certs = config.certs.relative_to(env.data_dir)
>>> rel_chains = config.chains.relative_to(env.data_dir)
>>> rel_policies = config.policies.relative_to(env.config_dir)

>>> rel_data = Path("test_data")
>>> _ = env.copy2data(rel_data / rel_certs/ "ca.crt.pem", rel_certs / "ca.crt.pem" )
>>> _ = env.copy2data(rel_data / rel_certs/ "Muster-Verband-Hamburg-Regional-CA_Hamburg.crt.pem", 
...                  rel_certs / "Muster-Verband-Hamburg-Regional-CA_Hamburg.crt.pem" )
>>> _ = env.copy2data(rel_data / rel_chains/ "all.chain.pem", rel_chains / "all.chain.pem" )

>>> _ = env.copy2config(rel_data / rel_policies / "ca_intermed_hamburg_conf.toml",
...            rel_policies / "ca_intermed_hamburg_conf.toml")
>>> _ = env.copy2config(rel_data / "private" / "inter1secret",
...            rel_private / "inter1secret")
>>> _ = env.copy2config(rel_data / "private" / "intermed1.key.pem",
...            rel_private / "intermed1.key.pem")

>>> _ = env.copy2data(rel_data / "intermed1.pub.pem", "intermed1.pub.pem" )
>>> _ = env.copy2cwd(rel_data / "Muster-Verband-Hamburg-Systems-Issuing-CA_Hamburg.csr",
...            "Muster-Verband-Hamburg-Systems-Issuing-CA_Hamburg.csr")



.. !SECTION
.. SECTION - Prepare

>>> from pathlib import Path


>>> def getpasswd(prompt:str)->str:
...     print(prompt)
...     return "secret"

>>> getpass.getpass = getpasswd

>>> cmd_line =  "--conf-file ca_intermed_hamburg_conf.toml"
>>> cmd_line += " -k intermed1 "
>>> cmd_line += " --private-dir .private"
>>> cmd_line += " --policy-name intermediate"
>>> cmd_line += " -t intermediate"
>>> cmd_line += " -c Muster-Verband-Hamburg-Regional-CA_Hamburg.crt.pem"
>>> cmd_line += " inter1secret"
>>> cmd_line += " Muster-Verband-Hamburg-Systems-Issuing-CA_Hamburg.csr"

>>> import shlex
>>> sys_argv= shlex.split(cmd_line) 
>>> sys_argv #doctest: +NORMALIZE_WHITESPACE
['--conf-file', 'ca_intermed_hamburg_conf.toml', 
 '-k', 'intermed1', 
 '--private-dir', '.private', 
 '--policy-name', 'intermediate', 
 '-t', 'intermediate', 
 '-c', 'Muster-Verband-Hamburg-Regional-CA_Hamburg.crt.pem', 
 'inter1secret', 
 'Muster-Verband-Hamburg-Systems-Issuing-CA_Hamburg.csr']

.. !SECTION

>>> from ftwpki.intermed_signer.programms import prog_intermediate_sign

>>> prog_intermediate_sign(sys_argv)
Enter Password:
0

>>> cmd_line =  "--conf-file ca_intermed_hamburg_conf.toml"
>>> cmd_line += " -k intermed1 "
>>> cmd_line += " --private-dir .private"
>>> cmd_line += " --policy-name intermediate"
>>> cmd_line += " -t intermediate"
>>> cmd_line += " -P 99 "
>>> cmd_line += " -c Muster-Verband-Hamburg-Regional-CA_Hamburg.crt.pem"
>>> cmd_line += " inter1secret"
>>> cmd_line += " Muster-Verband-Hamburg-Systems-Issuing-CA_Hamburg.csr"

>>> sys_argv= shlex.split(cmd_line) 

>>> prog_intermediate_sign(sys_argv)
Path length too high: 1
1

>>> cmd_line =  "--conf-file ca_intermed_hamburg_conf.toml"
>>> cmd_line += " -k intermed1 "
>>> cmd_line += " -C no "
>>> cmd_line += " -O no "
>>> cmd_line += " --private-dir .private"
>>> cmd_line += " --policy-name intermediate"
>>> cmd_line += " -t intermediate"
>>> cmd_line += " -c Muster-Verband-Hamburg-Regional-CA_Hamburg.crt.pem"
>>> cmd_line += " inter1secret"
>>> cmd_line += " Muster-Verband-Hamburg-Systems-Issuing-CA_Hamburg.csr"

>>> sys_argv= shlex.split(cmd_line) 

>>> prog_intermediate_sign(sys_argv)
While policyvalidation following missmatch occurs:
    - [countryName]: DISALLOWED
    - [organizationName]: DISALLOWED
1

>>> def key_inter(prompt):
...     raise KeyboardInterrupt


>>> getpass.getpass = key_inter

>>> cmd_line =  "--conf-file ca_intermed_hamburg_conf.toml"
>>> cmd_line += " -k intermed1 "
>>> cmd_line += " --private-dir .private"
>>> cmd_line += " --policy-name intermediate"
>>> cmd_line += " -t intermediate"
>>> cmd_line += " -c Muster-Verband-Hamburg-Regional-CA_Hamburg.crt.pem"
>>> cmd_line += " inter1secret"
>>> cmd_line += " Muster-Verband-Hamburg-Systems-Issuing-CA_Hamburg.csr"

>>> sys_argv= shlex.split(cmd_line) 

>>> prog_intermediate_sign(sys_argv)
1

>>> def throw_exception(prompt):
...     raise Exception("Test outer Exception.")


>>> getpass.getpass = throw_exception

>>> prog_intermediate_sign(sys_argv)
Test outer Exception.
1

.. SECTION - Teardown

>>> env.clean_home()
>>> env.teardown()

.. !SECTION
