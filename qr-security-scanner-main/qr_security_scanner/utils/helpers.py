"""
helpers.py
----------
Small reusable utilities shared across the app and services.
"""

import os
from typing import Any, Optional

import streamlit as st


def get_secret(key: str) -> Optional[str]:
    """
    Read a configuration value, or return None if it isn't set.

    Lookup order:
        1. Streamlit secrets (.streamlit/secrets.toml locally, or the
           "Secrets" box on Streamlit Community Cloud)
        2. Environment variable of the same name (used by Docker and most
           other hosting platforms)

    Never raises: callers decide how to handle a missing key and show a
    friendly "not configured" message instead of crashing.

    Values are stripped of surrounding whitespace/newlines, because a key
    copy-pasted from a browser or terminal often picks up a trailing space
    that silently turns a valid key into an "invalid key" API error.
    """
    value: Any = None
    try:
        value = st.secrets.get(key)
    except Exception:
        value = None

    if not value:
        value = os.environ.get(key)

    if isinstance(value, str):
        value = value.strip()
    return value or None


def extract_error_message(response: Any) -> Optional[str]:
    """
    Best-effort extraction of a human-readable error message from a
    failed API response (VirusTotal or Gemini both use a JSON body
    shaped like {"error": {"message": "..."}} on failure).

    Returns None if no message could be found — callers fall back to
    their own generic message in that case.
    """
    try:
        data = response.json()
    except ValueError:
        text = (getattr(response, "text", "") or "").strip()
        return text[:200] if text else None

    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            if message:
                return str(message)
        elif isinstance(error, str) and error:
            return error
    return None
