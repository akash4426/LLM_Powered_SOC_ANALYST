from openai import OpenAI
import json

client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")

response = client.chat.completions.create(
    model="qwen3:4b",
    messages=[{"role": "user", "content": "Please output a JSON with a single key 'hello' and value 'world' and nothing else."}]
)

print("--- RAW OBJECT ---")
print(response)

print("--- MODEL DUMP ---")
print(json.dumps(response.model_dump(), indent=2))

content = response.choices[0].message.content
print(f"--- CONTENT --- (type: {type(content)})")
print(content)
