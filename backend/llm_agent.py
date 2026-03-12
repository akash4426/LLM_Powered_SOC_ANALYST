import os
import google.generativeai as genai
from dotenv import load_dotenv
from backend.rag_engine import retrieve_context

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("gemini-2.5-flash")


def investigate_logs(log_text: str):

    context = retrieve_context(log_text)

    prompt = f"""
You are an expert SOC security analyst.

Analyze the following security logs and identify suspicious activity.

Logs:
{log_text}

Relevant cybersecurity knowledge:
{context}

Return JSON with:
attack_stage
mitre_technique
severity
confidence
explanation
recommended_actions
"""

    response = model.generate_content(prompt)

    return response.text