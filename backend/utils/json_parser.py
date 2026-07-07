"""
json_parser.py — Robust JSON Parser
=====================================

Provides resilient JSON parsing for LLM outputs. Handles markdown code fences,
truncated outputs, trailing commas, and unescaped strings often produced by
local models like Ollama.
"""

import json
import re
import ast
from typing import Optional, Dict, Any

def repair_and_parse_json(raw_str: str) -> Optional[Dict[str, Any]]:
    """Attempt to parse a potentially malformed JSON string into a dict."""
    
    # 1. Clean markdown code fences
    text = re.sub(r'```(?:json)?\n?(.*?)\n?```', r'\1', raw_str, flags=re.DOTALL)
    
    # 2. Extract first valid {...} block
    match = re.search(r'\{.*\}', text, flags=re.DOTALL)
    if match:
        text = match.group(0)
    else:
        # Might be missing closing brace due to truncation
        start = text.find('{')
        if start != -1:
            text = text[start:]
            
    # 3. Fix trailing commas (common LLM mistake)
    text = re.sub(r',\s*([\]}])', r'\1', text)
    
    # 4. Try standard JSON parsing
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
        
    # 5. Iterative truncation repair
    # Try closing the JSON string with various combinations
    for closing in ['}', '"}', '"]}', ']}', '""}', '"]}']:
        try:
            return json.loads(text + closing)
        except json.JSONDecodeError:
            pass
            
    # 6. Try fixing unescaped newlines or quotes inside strings using AST
    try:
        safe_eval_text = text.replace("null", "None").replace("true", "True").replace("false", "False")
        # Fix actual unescaped newlines which break AST
        safe_eval_text = safe_eval_text.replace('\n', '\\n')
        parsed = ast.literal_eval(safe_eval_text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
        
    return None
