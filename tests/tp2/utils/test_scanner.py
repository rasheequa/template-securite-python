import pytest

from src.tp2.utils.scanner import YaraScanner

RULE_ABC = 'rule Test_Abc { strings: $a = "abc" condition: $a }'
RULE_XYZ = 'rule Test_Xyz { strings: $a = "xyz" condition: $a }'


@pytest.mark.parametrize(
    "rules, data, expected",
    [
        ([RULE_ABC], b"xxabcxx", ["Test_Abc"]),
        ([RULE_ABC], b"nothing here", []),
        ([RULE_ABC, RULE_XYZ], b"abc xyz", ["Test_Abc", "Test_Xyz"]),
        ([RULE_ABC, RULE_XYZ], b"xyz", ["Test_Xyz"]),
        (["rule Broken { oops }"], b"abc", []),
        ([], b"abc", []),
    ],
    ids=["match", "no_match", "two_rules", "one_of_two", "broken_rule", "no_rule_file"],
)
def test_scan(tmp_path, rules, data, expected):

    for i, rule in enumerate(rules):
        (tmp_path / f"rule{i}.yar").write_text(rule)

    scanner = YaraScanner(tmp_path)

    assert sorted(scanner.scan(data)) == sorted(expected)


def test_scan_missing_folder(tmp_path):

    scanner = YaraScanner(tmp_path / "does_not_exist")

    assert scanner.scan(b"abc") == []
