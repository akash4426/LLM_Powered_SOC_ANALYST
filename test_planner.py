import os
from dotenv import load_dotenv
load_dotenv(override=True)
from backend.reasoning.planner import generate_plan
import logging

logging.basicConfig(level=logging.INFO)

# Test dummy object
dummy_obj = {
    "session_metadata": {"total_events": 5},
    "normalized_events": [],
    "entity_info": {"primary_entity": "192.168.1.50"}
}

plan = generate_plan(dummy_obj)
print("FINAL PLAN:", plan)
