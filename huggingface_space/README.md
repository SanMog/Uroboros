## 🐍 Uroboros — HuggingFace Space

Этот каталог содержит минимальную обёртку для запуска Uroboros как веб‑приложения на HuggingFace Spaces.

### Что делает приложение

- **Target model**: выбираете модель, которую хотите протестировать:
  - `gpt-4o-mini`
  - `gpt-4o`
  - `groq/llama-3.3-70b-versatile`
- **Attack suite**:
  - `injection` — OWASP LLM01 Prompt Injection
  - `hallucination` — OWASP LLM09 Overreliance / Hallucination
  - `pii` — OWASP LLM06 Sensitive Information Disclosure
  - `all` — все три категории сразу
- **Run Attack**:
  - внутри вызывается `UroborosPipeline` (статический скан);
  - строятся payload’ы так же, как в CLI (`uroboros run`);
  - результаты показываются в таблице:
    - **Attack** — OWASP tag (LLM01 / LLM06 / LLM09)
    - **Score** — итоговый балл 0–100
    - **Risk** — `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `SAFE`
    - **Reason** — краткое объяснение вердикта
  - внизу summary:
    - **Vulnerability rate** (доля уязвимых ответов)
    - **Critical findings count** (сколько критических выводов)

### Поля интерфейса

- **API key (OpenAI or Groq)**  
  Введите действующий API‑ключ:
  - для моделей OpenAI (`gpt-4o-mini`, `gpt-4o`) — ключ OpenAI;
  - для моделей Groq (`groq/llama-3.3-70b-versatile`) — ключ Groq.

  Внутри приложения ключ кладётся в переменные окружения:

  - `OPENAI_API_KEY` — для моделей OpenAI;
  - `GROQ_API_KEY` — для моделей Groq.

- **Target model** — строка модели, которая пойдёт в LiteLLM через `BlueTeam`.
- **Attack suite** — выбор набора атак (см. выше).
- **Run Attack** — запускает полный цикл Red → Blue → Judge для выбранного набора payload’ов.

### Как использовать на HuggingFace

1. Создайте новый Space (тип **Gradio**).
2. Скопируйте содержимое каталога `huggingface_space/` в корень Space:
   - `app.py`
   - `requirements.txt`
   - (опционально) этот `README.md` как описание репозитория.
3. В настройках Space добавьте секреты:
   - `OPENAI_API_KEY` — если используете модели OpenAI;
   - `GROQ_API_KEY` — если используете Groq.
4. Дождитесь установки зависимостей и автозапуска Space.

### Зависимости

Указываются в `huggingface_space/requirements.txt` и включают:

- `gradio` — веб‑интерфейс;
- `uroboros` (v0.2.0) — сам фреймворк;
- `litellm` — унифицированный доступ к LLM провайдерам;
- `python-dotenv` — для совместимости с конфигурацией Uroboros.

