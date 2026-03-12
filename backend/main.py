from fastapi import FastAPI
from backend.models import LogRequest
from backend.log_parser import parse_logs
from backend.llm_agent import investigate_logs

app = FastAPI(title="LLM Powered SOC Analyst")


@app.get("/")
def home():
    return {"status": "SOC Analyst API Running"}


@app.post("/investigate")
def investigate(request: LogRequest):

    parsed_logs = parse_logs(request.logs)

    result = investigate_logs(request.logs)

    return {
        "parsed_logs": parsed_logs,
        "investigation": result
    }