from unittest.mock import MagicMock

from src.tp3.main import breach_network, breach_web


def test_breach_web():
    # Given
    session = MagicMock()
    session.prepare_request.return_value = "ESGI{web_dev-local-flag}"

    # When
    breach_web(session)

    # Then
    session.prepare_request.assert_called_once()


def test_breach_network():
    # Given
    session = MagicMock()
    session.get_flag.return_value = "ESGI{chain_dev-local-flag}"

    # When
    result = breach_network(session)

    # Then
    session.submit_request.assert_called_once()
    assert result == "ESGI{chain_dev-local-flag}"
