import json
import sys

import pytest

from src.tp2.main import main, parse_args

SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
RULE = 'rule Test_Abc { strings: $a = "abc" condition: $a }'


@pytest.mark.parametrize(
    "argv, expected",
    [
        (
            ["--samples", "s", "--rules", "r", "--out", "o"],
            {"samples": "s", "rules": "r", "out": "o", "llm": "openrouter"},
        ),
        (
            ["--samples", "s", "--rules", "r", "--out", "o", "--llm", "ollama"],
            {"samples": "s", "rules": "r", "out": "o", "llm": "ollama"},
        ),
    ],
    ids=["default_llm", "ollama"],
)
def test_parse_args(argv, expected):

    args = parse_args(argv)

    assert vars(args) == expected


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--samples", "s"],
        ["--samples", "s", "--rules", "r"],
        ["--samples", "s", "--rules", "r", "--out", "o", "--llm", "x"],
    ],
    ids=["nothing", "only_samples", "no_out", "unknown_llm"],
)
def test_parse_args_invalid(argv):

    with pytest.raises(SystemExit):
        parse_args(argv)


def test_main(tmp_path, monkeypatch):

    samples = tmp_path / "samples"
    rules = tmp_path / "rules"
    out = tmp_path / "out"
    samples.mkdir()
    rules.mkdir()
    (samples / "a.bin").write_bytes(b"abc")
    (samples / "folder").mkdir()
    (rules / "r.yar").write_text(RULE)
    monkeypatch.setattr(
        sys, "argv", ["tp2", "--samples", str(samples), "--rules", str(rules), "--out", str(out)]
    )

    main()

    result = json.loads((out / "a.bin.triage.json").read_text(encoding="utf-8"))
    assert result["sha256"] == SHA256
    assert result["yara_matches"] == ["Test_Abc"]
    assert json.loads((out / "a.triage.json").read_text(encoding="utf-8")) == result
    assert json.loads((out / f"{SHA256}.json").read_text(encoding="utf-8")) == result
    assert (out / "a.bin.triage.pdf").read_bytes()[:5] == b"%PDF-"


def test_main_missing_samples_folder(tmp_path, monkeypatch):

    out = tmp_path / "out"
    monkeypatch.setattr(
        sys, "argv", ["tp2", "--samples", str(tmp_path / "nope"), "--rules", str(tmp_path), "--out", str(out)]
    )

    main()

    assert list(out.iterdir()) == []
