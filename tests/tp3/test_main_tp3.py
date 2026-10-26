import sys
from unittest.mock import MagicMock

from src.tp3.main import breach_network, breach_web, main


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


def test_main(monkeypatch):
    # Given
    monkeypatch.setattr(sys, "argv", ["tp3", "--target", "http://example.com:8080"])
    fake_session = MagicMock()
    fake_session.get_flag.return_value = "ESGI{chain_dev-local-flag}"
    session_class = MagicMock(return_value=fake_session)
    monkeypatch.setattr("src.tp3.main.Session", session_class)

    # When
    main()

    # Then
    session_class.assert_called_once_with("http://example.com:8080")
    fake_session.prepare_request.assert_called_once()
    fake_session.submit_request.assert_called_once()
