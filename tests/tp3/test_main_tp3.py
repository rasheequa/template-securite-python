from unittest.mock import MagicMock

from src.tp3.main import breach_web


def test_breach_web():
    # Given
    session = MagicMock()
    session.prepare_request.return_value = "ESGI{web_dev-local-flag}"

    # When
    breach_web(session)

    # Then
    session.prepare_request.assert_called_once()
