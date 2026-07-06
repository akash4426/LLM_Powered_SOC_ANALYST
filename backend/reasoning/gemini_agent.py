"""
gemini_agent.py
---------------
Google Gemini fallback LLM agent for the SOC Analyst pipeline.

Uses the new `google-genai` SDK (google-genai >= 0.7).
Activated automatically by llm_agent.py when the primary LLM
(Ollama / OpenRouter) is unavailable or returns an error.

Environment variable:
    GEMINI_API_KEY  — Google AI Studio API key (free tier available at
                      https://aistudio.google.com/app/apikey)

Model:
    gemini-2.0-flash  — fast, free-tier capable
"""

import os
import logging

logger = logging.getLogger(__name__)

_GEMINI_MODEL = "gemini-2.5-flash"


def _get_client():
    """Lazily create the Gemini client. Raises RuntimeError if key missing."""
    try:
        from google import genai  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            "google-genai is not installed. "
            "Run: pip install google-genai"
        ) from e

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set in environment. "
            "Get a free key from https://aistudio.google.com/app/apikey "
            "and add it to your .env file."
        )

    client = genai.Client(api_key=api_key)
    return client


def generate_gemini_inference(prompt: str) -> str:
    """
    Execute a Gemini inference call using the google-genai SDK.

    Args:
        prompt: The full SOC analyst prompt string.

    Returns:
        Raw text response from Gemini.

    Raises:
        RuntimeError: If the API key is missing, the package is not
                      installed, or the API call itself fails.
    """
    from google import genai  # type: ignore
    from google.genai import types  # type: ignore

    client = _get_client()

    try:
        response = client.models.generate_content(
            model=_GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.3,
                max_output_tokens=2000,
                response_mime_type="application/json",
            ),
        )

        text = response.text
        if not text or not text.strip():
            raise RuntimeError("Gemini returned an empty response.")

        logger.info(f"[Gemini] Inference successful ({len(text)} chars) via {_GEMINI_MODEL}.")
        return text.strip()

    except Exception as e:
        logger.error(f"[Gemini] Inference failed: {e}")
        raise RuntimeError(f"Gemini inference failed: {e}") from e


def is_gemini_available() -> bool:
    """
    Quick check: returns True if the Gemini API key is configured
    and the google-genai package is installed. Does NOT make a network call.
    """
    try:
        from google import genai  # noqa: F401
        return bool(os.getenv("GEMINI_API_KEY", "").strip())
    except ImportError:
        return False