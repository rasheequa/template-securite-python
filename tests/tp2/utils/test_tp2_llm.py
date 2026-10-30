import pytest

from src.tp2.utils.llm import SYSTEM_PROMPT, LLMTriage


@pytest.mark.parametrize("backend", ["openrouter", "ollama"], ids=["openrouter", "ollama"])
def test_llm_triage_init(backend):
    llm = LLMTriage(backend)

    assert llm.backend == backend


def test_llm_triage_not_implemented():
    """The triage is deterministic only: the LLM call is not implemented and never made."""

    llm = LLMTriage("openrouter")

    with pytest.raises(NotImplementedError):
        llm.triage("{}")


def test_system_prompt_warns_against_injection():
    assert "PAS fiables" in SYSTEM_PROMPT
    assert "JSON" in SYSTEM_PROMPT
