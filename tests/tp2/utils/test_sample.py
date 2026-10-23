
from src.tp2.utils.sample import Sample


def test_get_file_metadata(tmp_path):

    file = tmp_path / "test.bin"
    file.write_bytes(b"abc")

    sample = Sample(str(file))
    metadata = sample.get_file_metadata()

    sha256 = metadata["sha256"]
    md5 = metadata["md5"]
    size = metadata["size"]
    file_type = metadata["file_type"]
    entropy = metadata["entropy"]

    assert sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert size == 3
    assert "ASCII text" in file_type
    assert entropy == 1.58
