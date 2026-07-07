"""
llm_gateway.py
--------------
Pure LLM Provider Interface.

This module handles API communication based on the environment:
- Local:      Ollama (Primary)
- Production: OpenRouter (Primary) → Gemini (Fallback 1) → Ollama (Fallback 2)

V1 FIX: Exposes a `ReasoningProvider` class so all callers (Planner, Reflection,
Report Generator) depend ONLY on the abstract interface, never on a concrete model.
The planner must never know which model is used.
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_GEMINI_MODEL = "gemini-2.5-flash"


class ReasoningProvider:
    """
    V1 FIX: Abstract interface for LLM inference.
    
    All components that need LLM access must use:
        provider = ReasoningProvider()
        result = provider.generate(prompt, json_mode=True)
        
    They must NEVER call generate_reasoning() or any _generate_*() function directly.
    This decouples all callers from the concrete provider selection logic.
    """

    def generate(self, prompt: str, json_mode: bool = True) -> str:
        """Generate a response. Automatically selects the best available provider."""
        return generate_reasoning(prompt, json_mode)

    def generate_json(self, prompt: str) -> str:
        """Convenience method for JSON-mode generation."""
        return self.generate(prompt, json_mode=True)

    def generate_text(self, prompt: str) -> str:
        """Convenience method for free-text generation."""
        return self.generate(prompt, json_mode=False)


def is_gemini_available() -> bool:
    """Check if Gemini API key and SDK are available."""
    try:
        from google import genai
        return bool(os.getenv("GEMINI_API_KEY", "").strip())
    except ImportError:
        return False


def _generate_gemini(prompt: str, json_mode: bool = True) -> str:
    from google import genai
    from google.genai import types

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    client = genai.Client(api_key=api_key)

    try:
        response = client.models.generate_content(
            model=_GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.3,
                max_output_tokens=2000,
                response_mime_type="application/json" if json_mode else "text/plain",
            ),
        )

        text = response.text
        if not text or not text.strip():
            raise RuntimeError("Gemini returned an empty response.")

        logger.info(f"[Gemini] Inference successful via {_GEMINI_MODEL}.")
        return text.strip()
    except Exception as e:
        raise RuntimeError(f"Gemini inference failed: {e}") from e


def _generate_openai_compatible(
    prompt: str, 
    json_mode: bool, 
    base_url: str, 
    api_key: str, 
    model_name: str, 
    is_openrouter: bool
) -> str:
    from openai import OpenAI

    client = OpenAI(base_url=base_url, api_key=api_key, timeout=None)  # No timeout for local models
    
    kwargs = {
        "model": model_name,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 2000,
        "temperature": 0.3,
    }

    # Special headers for OpenRouter
    if is_openrouter:
        kwargs["extra_headers"] = {
            "HTTP-Referer": "http://localhost:8000", 
            "X-Title": "SOC Analyst Platform"
        }

    response = client.chat.completions.create(**kwargs)

    if isinstance(response, dict):
        if "error" in response:
            raise RuntimeError(f"API Error: {response['error']}")
        return response.get("choices", [{}])[0].get("message", {}).get("content", "").strip()

    message_obj = response.choices[0].message
    text = message_obj.content or ""
    
    # Workaround for reasoning models (e.g., Qwen R1/DeepSeek) that may put the JSON entirely 
    # inside their "thinking" or "reasoning" block and leave the main content empty.
    raw_dict = response.model_dump() if hasattr(response, "model_dump") else {}
    msg_dict = raw_dict.get("choices", [{}])[0].get("message", {})
    reasoning = msg_dict.get("reasoning", "") or msg_dict.get("reasoning_content", "")
    
    if reasoning:
        text = text + "\n" + reasoning

    if not text or not text.strip():
        raise RuntimeError("LLM returned empty content.")

    logger.info(f"[OpenAI-Compatible] Inference succeeded via {base_url} (model: {model_name})")
    return text.strip()


def _generate_ollama(prompt: str, json_mode: bool) -> str:
    import requests
    
    # We strip /v1 if the user configured the OpenAI base URL, to reach the root Ollama API
    base_url = os.getenv("OPENAI_BASE_URL", "http://localhost:11434/v1").replace("/v1", "")
    if not base_url:
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    
    model_name = os.getenv("OLLAMA_MODEL") or os.getenv("OPENROUTER_MODEL", "qwen3:4b")
    
    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "options": {
            # Tuned for qwen3:4b on Apple M2 Air (8-16GB RAM):
            # - num_ctx=4096: safe context window that fits in unified memory
            # - num_predict=1500: enough tokens for JSON plans + reports
            # - temperature=0.1: lower temp = more deterministic JSON output, fewer parse retries
            # - num_thread=0: let Ollama auto-detect optimal thread count for M2
            "temperature": 0.1,
            "num_predict": 1500,
            "num_ctx": 8192,
            "num_thread": 0,
        }
    }
    
    if json_mode:
        payload["format"] = "json"

    try:
        response = requests.post(f"{base_url}/api/generate", json=payload, timeout=None)  # No timeout
        response.raise_for_status()
        data = response.json()
        
        # Native Ollama API separates "response" and "thinking" cleanly
        text = data.get("response", "")
        
        # If the model still somehow dumps it in thinking and leaves response empty
        if not text.strip():
            text = data.get("thinking", "")
            
        if not text.strip():
            raise RuntimeError("Ollama returned empty content.")
            
        logger.info(f"[Ollama Native] Inference succeeded via {base_url} (model: {model_name})")
        return text.strip()
        
    except Exception as e:
        raise RuntimeError(f"Ollama native API failed: {e}")


def _generate_openrouter(prompt: str, json_mode: bool) -> str:
    api_key = os.getenv("OPEN_ROUTER_API") or os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY not set")
    base_url = "https://openrouter.ai/api/v1"
    model_name = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3-70b-instruct")
    return _generate_openai_compatible(prompt, json_mode, base_url, api_key, model_name, is_openrouter=True)


def generate_reasoning(prompt: str, json_mode: bool = True) -> str:
    """
    Execute LLM inference.
    
    Local: Gemini (Primary if available) -> Ollama (Fallback)
    Production: OpenRouter -> Gemini -> Ollama
    """
    env = os.getenv("ENV", "local").lower()

    if env == "production":
        # 1. OpenRouter
        try:
            return _generate_openrouter(prompt, json_mode)
        except Exception as e1:
            logger.warning(f"[Gateway] OpenRouter failed: {e1}. Trying Gemini...")
            
            # 2. Gemini
            if is_gemini_available():
                try:
                    return _generate_gemini(prompt, json_mode)
                except Exception as e2:
                    logger.warning(f"[Gateway] Gemini failed: {e2}. Trying Ollama...")
            else:
                logger.warning("[Gateway] Gemini not available (API key missing). Trying Ollama...")
                
            # 3. Ollama
            try:
                return _generate_ollama(prompt, json_mode)
            except Exception as e3:
                raise RuntimeError(f"All production providers failed. Final Ollama error: {e3}")
    else:
        # Local
        if is_gemini_available():
            try:
                return _generate_gemini(prompt, json_mode)
            except Exception as e:
                logger.warning(f"[Gateway] Local Gemini failed: {e}. Trying Ollama...")

        try:
            return _generate_ollama(prompt, json_mode)
        except Exception as e:
            logger.error(f"[Gateway] Local Ollama failed: {e}")
            raise RuntimeError(f"Local Ollama failed: {e}")
