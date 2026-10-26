import json

import pytest

from src.tp2.utils.report import Report

FULL_RESULT = {
    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "size": 3,
    "iocs": {"domains": ["c2.example.test"], "ips": ["185.10.20.30"]},
    "yara_matches": ["Has_Mutex"],
    "llm_summary": "Dropper contacting c2.example.test",
    "score": 8,
}


@pytest.mark.parametrize(
    "result",
    [
        FULL_RESULT,
        {"sha256": "abc", "size": 0},
        {},
        {"llm_summary": "accents é and arrow → kept in json"},
    ],
    ids=["full", "metadata_only", "empty", "unicode"],
)
def test_generate_json(tmp_path, result):

    file = tmp_path / "test_generate_json.json"

    report = Report(result)
    report.generate_json(file)

    assert json.loads(file.read_text(encoding="utf-8")) == result


@pytest.mark.parametrize(
    "result",
    [
        FULL_RESULT,
        {"sha256": "abc", "size": 0},
        {},
        {"llm_summary": None},
        {"llm_summary": ""},
        {"llm_summary": 42},
        {"llm_summary": "arrow → emoji \U0001f600 accent é"},
        {"llm_summary": "A" * 400},
        dict(FULL_RESULT, imports=[f"api_{i}" for i in range(200)]),
        dict(FULL_RESULT, iocs=None),
        dict(FULL_RESULT, iocs={"domains": ["x" * 300] * 5, "ips": "1.2.3.4", "mutex": None}),
        dict(FULL_RESULT, iocs={"registry": ["\u00e9\u2192\U0001f600"]}, mitre_attack=None, flag=None),
    ],
    ids=[
        "full",
        "metadata_only",
        "empty",
        "summary_none",
        "summary_empty",
        "summary_number",
        "summary_unicode",
        "summary_long_word",
        "many_imports",
        "no_iocs",
        "odd_ioc_values",
        "unicode_ioc_and_missing_fields",
    ],
)
def test_generate_pdf(tmp_path, result):

    file = tmp_path / "test_generate_pdf.pdf"

    report = Report(result)
    report.generate_pdf(str(file))

    assert file.read_bytes()[:5] == b"%PDF-"
