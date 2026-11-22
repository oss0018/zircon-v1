import zipfile

import pytest

from app.services.ukraine_registry_snapshot import SnapshotError, SnapshotStats, read_company_snapshot


XML = """<?xml version="1.0" encoding="windows-1251"?>
<DATA FORMAT_VERSION="1.0">
<SUBJECT><RECORD>1</RECORD><NAME>Компанія</NAME><EDRPOU>01234567</EDRPOU>
<STAN>зареєстровано</STAN><SIGNERS><SIGNER>Приклад - керівник</SIGNER></SIGNERS></SUBJECT>
</DATA>""".encode("cp1251")


def test_official_zip_reads_only_company_member(tmp_path):
    path = tmp_path / "snapshot.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("17.1-EX_XML_EDR_FOP_FULL.xml", b"<DATA>not a company</DATA>")
        archive.writestr("17.1-EX_XML_EDR_UO_FULL.xml", XML)
    assert list(read_company_snapshot(path)) == [{
        "edrpou": "01234567", "name": "Компанія", "short_name": "",
        "status": "зареєстровано", "signatories": ["Приклад - керівник"],
    }]


def test_xml_and_invalid_archives(tmp_path):
    path = tmp_path / "company.xml"
    path.write_bytes(XML)
    assert list(read_company_snapshot(path))[0]["edrpou"] == "01234567"
    path.write_bytes(XML.replace(b"01234567", b"invalid"))
    with pytest.raises(SnapshotError, match="EDRPOU"):
        list(read_company_snapshot(path))
    archive_path = tmp_path / "missing.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("FOP_FULL.xml", XML)
    with pytest.raises(SnapshotError, match="UO company"):
        list(read_company_snapshot(archive_path))


def test_xml_entities_are_rejected(tmp_path):
    path = tmp_path / "company.xml"
    path.write_text(
        '<!DOCTYPE DATA [<!ENTITY x "test">]><DATA><SUBJECT><EDRPOU>01234567</EDRPOU>'
        '<NAME>&x;</NAME></SUBJECT></DATA>', encoding="utf-8"
    )
    with pytest.raises(SnapshotError, match="Invalid snapshot XML"):
        list(read_company_snapshot(path))


def test_missing_codes_are_retained_and_reported_when_explicitly_requested(tmp_path):
    path = tmp_path / "company.xml"
    path.write_bytes(XML.replace(b"</DATA>", b"<SUBJECT><EDRPOU></EDRPOU><NAME>Missing</NAME></SUBJECT></DATA>"))
    with pytest.raises(SnapshotError, match="EDRPOU"):
        list(read_company_snapshot(path))
    stats = SnapshotStats()
    records = list(read_company_snapshot(path, stats))
    assert len(records) == 2 and records[1]["edrpou"] is None
    assert stats.missing_edrpou == 1
