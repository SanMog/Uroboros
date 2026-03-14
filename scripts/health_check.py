import os
from dotenv import load_dotenv
load_dotenv()

import litellm
litellm.suppress_debug_info = True

models = [
    "gpt-4o-mini",
    "claude-haiku-4-5-20251001",
    "groq/llama-3.3-70b-versatile",
    "gemini/gemini-3-flash-preview",
    "gemini/gemini-2.5-flash",
]

for model in models:
    try:
        resp = litellm.completion(
            model=model,
            messages=[{"role": "user", "content": "say pong"}],
            max_tokens=5,
        )
        print(f"✅ {model}: {resp.choices[0].message.content.strip()}")
    except Exception as e:
        print(f"❌ {model}: {str(e)[:80]}")