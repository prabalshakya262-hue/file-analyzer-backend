import openai
import requests
import json
from ..config import settings

def generate_report(file_id, file_path, raw_results):
    if settings.LLM_PROVIDER == "openai":
        markdown, json_out = generate_with_openai(file_id, file_path, raw_results)
    elif settings.LLM_PROVIDER == "ollama":
        markdown, json_out = generate_with_ollama(file_id, file_path, raw_results)
    else:
        markdown = fallback_report(file_id, raw_results)
        json_out = None
    return markdown, json_out

def generate_with_openai(file_id, file_path, raw_results):
    openai.api_key = settings.OPENAI_API_KEY
    prompt = build_prompt(file_id, file_path, raw_results)
    try:
        response = openai.ChatCompletion.create(
            model=settings.LLM_MODEL,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=4000,
            response_format={"type": "json_object"} if settings.LLM_MODEL.startswith("gpt-4") else None
        )
        content = response.choices[0].message.content
        try:
            data = json.loads(content)
            markdown = data.get("markdown", content)
            json_out = data.get("structured", None)
        except:
            markdown = content
            json_out = None
        return markdown, json_out
    except Exception as e:
        return fallback_report(file_id, raw_results), None

def generate_with_ollama(file_id, file_path, raw_results):
    prompt = build_prompt(file_id, file_path, raw_results)
    try:
        response = requests.post(
            f"{settings.OLLAMA_URL}/api/generate",
            json={
                "model": settings.LLM_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json"
            }
        )
        if response.status_code == 200:
            content = response.json().get("response", "")
            try:
                data = json.loads(content)
                markdown = data.get("markdown", content)
                json_out = data.get("structured", None)
            except:
                markdown = content
                json_out = None
            return markdown, json_out
    except Exception:
        pass
    return fallback_report(file_id, raw_results), None

def build_prompt(file_id, file_path, raw_results):
    return f"""
You are a senior security analyst. Analyze the following application and produce a comprehensive report.

File ID: {file_id}
File Type: {raw_results.get('file_type')}

Analysis Results (JSON):
```json
{json.dumps(raw_results, indent=2, default=str)}