from unittest.mock import patch

from ftwpki.intermed.programms import prog_intermediate_sign



def test_prog_intermed_sign_invalid_dn(mocker, tmp_path):
    # Setup: Mocke die DN-Validierung auf 'is_valid = False'
    mock_val = mocker.patch("ftwpki.intermed.programms.ValidatorDN")
    mock_val.return_value.validate.return_value.is_valid = False
    mock_val.return_value.validate.return_value.errors = ["Country mismatch"]

    # Aufruf der Funktion
    # from ftwpki.intermed.programms import prog_intermed_sign

    result = prog_intermediate_sign(["--conf-file", "dummy.toml", "node-01.csr"])

    # Assert: Muss 1 zurückgeben
    assert result == 1

def test_prog_intermed_sign_path_length_error(mocker):
    # 1. Mocke den Parser, damit wir keine echten Files brauchen
    mock_args = mocker.Mock()
    mock_args.policy_name = "intermediate"
    mock_args.path_length = 5
    mock_args.certificate = "fake_ca.crt"
    mocker.patch("ftwpki.intermed.programms.CSRMultiSigningParser.parse_args", 
                 return_value=mock_args)

    # 2. Mocke das Laden des Zertifikats und simuliere eine zu kleine Path Length (z.B. 2)
    mock_cert = mocker.Mock()
    # Simuliere die Struktur: extensions -> BasicConstraints -> value -> path_length
    mock_bc = mocker.Mock()
    mock_bc.value.path_length = 2
    mock_cert.extensions.get_extension_for_class.return_value = mock_bc
    mocker.patch("ftwpki.intermed.programms.load_certificate_from_pem", return_value=mock_cert)
    mocker.patch("pathlib.Path.read_bytes", return_value=b"fake_data")

    # 3. Ausführung
    # Da 2 <= 5 ist, sollte dein Programm den Error-Zweig (Return 1) nehmen
    result = prog_intermediate_sign(["--any", "args"])

    assert result == 1

def test_prog_intermediate_sign_validation_error(mocker):
    # Mocke den Validator so, dass er einen Fehler liefert
    mock_val = mocker.patch("ftwpki.intermed.programms.ValidatorDN")
    mock_val.return_value.validate.return_value.is_valid = False
    mock_val.return_value.validate.return_value.errors = ["Country mismatch"]

    # Mocke das Drumherum (Parser etc.), damit keine echten Files geladen werden
    mocker.patch("ftwpki.intermed.programms.CSRMultiSigningParser.parse_args")
    mocker.patch("ftwpki.intermed.programms.load_certificate_from_pem")
    mocker.patch("pathlib.Path.read_bytes", return_value=b"data")


    # Das Programm muss hier mit 1 abbrechen
    assert prog_intermediate_sign([]) == 1

def test_prog_intermediate_sign_path_length_too_deep(mocker):
    # Mocke args: policy ist intermediate, gewollte Länge ist 5
    mock_args = mocker.Mock(policy_name="intermediate", path_length=5, certificate="ca.crt")
    mocker.patch("ftwpki.intermed.programms.CSRMultiSigningParser.parse_args", 
                 return_value=mock_args)

    # Mocke CA-Zertifikat mit einer REST-Länge von nur 2
    mock_cert = mocker.Mock()
    mock_bc = mocker.Mock()
    mock_bc.value.path_length = 2  # Issuer erlaubt nur noch 2, User will 5
    mock_cert.extensions.get_extension_for_class.return_value = mock_bc
    mocker.patch("ftwpki.intermed.programms.load_certificate_from_pem", return_value=mock_cert)
    mocker.patch("pathlib.Path.read_bytes", return_value=b"data")


    assert prog_intermediate_sign([]) == 1

def test_prog_intermediate_sign_general_exception(mocker):
    # Simuliere einen unerwarteten Fehler beim Laden des Keys
    mocker.patch(
        "ftwpki.intermed.programms.load_private_key_from_pem", side_effect=RuntimeError("Krawumm")
    )

    # Restliches Setup minimal halten
    mocker.patch("ftwpki.intermed.programms.CSRMultiSigningParser.parse_args")
    # ... weitere nötige Mocks ...


    assert prog_intermediate_sign([]) == 1

def test_prog_intermediate_sign_interrupt(mocker):
    mocker.patch(
        "ftwpki.intermed.programms.CSRMultiSigningParser.parse_args", side_effect=KeyboardInterrupt
    )
    assert prog_intermediate_sign([]) == 1

def test_prog_intermediate_sign_exception(mocker):
    mocker.patch(
        "ftwpki.intermed.programms.CSRMultiSigningParser.parse_args",
        side_effect=RuntimeError("Unerwarteter Fehler"),
    )
    assert prog_intermediate_sign([]) == 1

def test_prog_intermediate_sign_full_flow(mocker):
    # 1. Mocke den CLI Parser und die Rückgabewerte (args & extensions)
    mock_args = mocker.Mock()
    mock_args.certificate = "ca.crt"
    mock_args.certificat_sign_request = "test.csr"
    mock_args.policy_name = "standalone"
    mock_args.policy_type = "standalone"
    mock_args.policy = {"CN": "match"}
    mock_args.private_dir = "privat"
    mock_args.passphrasefile = "pw.enc"
    mock_args.private_key = "ca.key"
    mock_args.validity_days = 365

    mocker.patch("ftwpki.intermed.programms.CSRMultiSigningParser.parse_args", 
                 return_value=mock_args)
    mocker.patch("ftwpki.intermed.programms.toml2dn_policy", return_value={})
    mocker.patch("ftwpki.intermed.programms.toml2ext_policy", return_value={})

    # 2. Mocke die Dateisystem-Ladebefehle
    mocker.patch("pathlib.Path.read_bytes", return_value=b"fake_pem_data")
    mocker.patch("ftwpki.intermed.programms.load_certificate_from_pem")
    mocker.patch("ftwpki.intermed.programms.load_csr_from_pem")
    mocker.patch("ftwpki.intermed.programms.load_private_key_from_pem")

    # 3. Mocke die Validierung (Happy Path: is_valid = True)
    mock_val = mocker.patch("ftwpki.intermed.programms.ValidatorDN")
    mock_val.return_value.validate.return_value.is_valid = True

    # 4. Mocke Passwort-Eingabe und Manager
    mocker.patch("getpass.getpass", return_value="strenggeheim")
    mocker.patch("ftwpki.intermed.programms.PasswordManager")

    # 5. Mocke den Signier-Vorgang und Export
    mocker.patch("ftwpki.intermed.programms.CertificateSigner")
    mocker.patch("ftwpki.intermed.programms.validate_and_clamp_validity")
    mocker.patch(
        "ftwpki.intermed.programms.encrypt_transport_package", return_value=b"zipped_content"
    )
    mock_write = mocker.patch("pathlib.Path.write_bytes")

    # AUSFÜHRUNG
    result = prog_intermediate_sign([])

    # PRÜFUNG
    assert result == 0
    # Sicherstellen, dass die Datei am Ende geschrieben wurde (Zeile 172)
    assert mock_write.called

def test_prog_intermediate_sign_validation_fails(mocker):
    # 1. Setup: Mocks für die Infrastruktur (Parser, Path, etc.)
    mocker.patch("ftwpki.intermed.programms.CSRMultiSigningParser.parse_args")
    mocker.patch("ftwpki.intermed.programms.toml2dn_policy", return_value={})
    mocker.patch("ftwpki.intermed.programms.toml2ext_policy", return_value={})
    mocker.patch("ftwpki.intermed.programms.load_certificate_from_pem")
    mocker.patch("ftwpki.intermed.programms.load_csr_from_pem")
    mocker.patch("pathlib.Path.read_bytes", return_value=b"fake_data")

    # 2. Den Validator so mocken, dass er Fehler liefert
    mock_val_class = mocker.patch("ftwpki.intermed.programms.ValidatorDN")
    mock_instance = mock_val_class.return_value

    # Wir simulieren ein ungültiges Ergebnis mit einer Liste von Fehlern
    mock_instance.validate.return_value.is_valid = False
    mock_instance.validate.return_value.errors = ["Organization mismatch", "CommonName missing"]

    from ftwpki.intermed.programms import prog_intermediate_sign

    # 3. Ausführung
    result = prog_intermediate_sign([])

    # 4. Überprüfung
    assert result == 1  # Muss Returncode 1 liefern
