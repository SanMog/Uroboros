# scripts/gemini_discovery.py
"""Находит все живые Gemini модели через Google API."""
import os
import requests
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
BASE = "https://generativelanguage.googleapis.com/v1beta"

def list_models():
    resp = requests.get(f"{BASE}/models?key={API_KEY}")
    return resp.json().get("models", [])

def test_model(model_id: str) -> tuple[bool, str]:
    url = f"{BASE}/{model_id}:generateContent?key={API_KEY}"
    body = {"contents": [{"parts": [{"text": "Reply with one word: ALIVE"}]}]}
    try:
        resp = requests.post(url, json=body, timeout=10)
        data = resp.json()
        if "candidates" in data:
            text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
            return True, text
        return False, str(data)[:80]
    except Exception as e:
        return False, str(e)[:80]

def main():
    print("\n🔍 GEMINI MODEL DISCOVERY\n" + "─"*50)
    models = list_models()
    print(f"Found {len(models)} models total\n")

    working = []
    for m in models:
        name = m.get("name", "")
        # Тестируем только generateContent модели
        if "generateContent" not in m.get("supportedGenerationMethods", []):
            continue
        ok, msg = test_model(name)
        icon = "✅" if ok else "❌"
        print(f"{icon} {name}: {msg}")
        if ok:
            # Конвертируем в litellm формат
            litellm_name = "gemini/" + name.replace("models/", "")
            working.append(litellm_name)

    print(f"\n✅ WORKING ({len(working)}):")
    for m in working:
        print(f"  --attacker {m}")

if __name__ == "__main__":
    main()