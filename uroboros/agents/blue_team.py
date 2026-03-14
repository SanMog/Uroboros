# uroboros/agents/blue_team.py
"""
Project Uroboros — Blue Team
Wrapper for the target model being tested.
Supports: OpenAI, Groq, Anthropic, any LiteLLM-compatible endpoint.
"""

from __future__ import annotations
import time
import logging
from typing import Any
from uuid import uuid4
from litellm import completion
from uroboros.core.schema import AttackPayload, BlueTeamResponse

logger = logging.getLogger(__name__)


class BlueTeam:
    """
    Sends AttackPayload to target model, returns BlueTeamResponse.
    Never raises — errors are captured in BlueTeamResponse.error.
    """

    def __init__(
        self,
        model:       str = "gpt-4o-mini",
        temperature: float = 0.7,
        max_tokens:  int = 1024,
        system_prompt: str = "You are a helpful assistant.",
        extra_params: dict[str, Any] | None = None,
    ):
        self.model         = model
        self.temperature   = temperature
        self.max_tokens    = max_tokens
        self.system_prompt = system_prompt
        self.extra_params  = extra_params or {}

    def respond(self, payload: AttackPayload) -> BlueTeamResponse:
        """Send attack to target model. Always returns BlueTeamResponse."""
        start_ms = time.monotonic()

        # Use custom system_prompt from payload metadata if provided
        system_prompt = payload.metadata.get("system_prompt", self.system_prompt)

        try:
            result = completion(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": payload.prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                **self.extra_params,
            )

            latency_ms    = int((time.monotonic() - start_ms) * 1000)
            response_text = result.choices[0].message.content or ""
            tokens_used   = getattr(result.usage, "total_tokens", 0)

            return BlueTeamResponse(
                attack_id=payload.attack_id,
                response_text=response_text,
                model_used=self.model,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
            )

        except Exception as e:
            latency_ms = int((time.monotonic() - start_ms) * 1000)
            logger.error(f"BlueTeam error for attack {payload.attack_id}: {e}")

            error_text = str(e).lower()
            if any(s in error_text for s in ("502", "503", "timeout", "connection")):
                raise

            return BlueTeamResponse(
                attack_id=payload.attack_id,
                response_text="",
                model_used=self.model,
                latency_ms=latency_ms,
                error=str(e),
            )

    def respond_turn(
        self,
        messages: list[dict[str, str]],
        user_content: str,
        attack_id: str | None = None,
    ) -> BlueTeamResponse:
        """
        Multi-turn: append user message to history, call model, return response.
        messages must start with system (or be empty — then self.system_prompt is used).
        """
        aid = attack_id or f"drift_{uuid4().hex[:12]}"
        if not messages:
            messages = [{"role": "system", "content": self.system_prompt}]
        turn_messages = messages + [{"role": "user", "content": user_content}]
        start_ms = time.monotonic()
        try:
            result = completion(
                model=self.model,
                messages=turn_messages,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                **self.extra_params,
            )
            latency_ms = int((time.monotonic() - start_ms) * 1000)
            response_text = result.choices[0].message.content or ""
            tokens_used = getattr(result.usage, "total_tokens", 0)
            return BlueTeamResponse(
                attack_id=aid,
                response_text=response_text,
                model_used=self.model,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
            )
        except Exception as e:
            latency_ms = int((time.monotonic() - start_ms) * 1000)
            logger.error(f"BlueTeam respond_turn error [{aid}]: {e}")
            error_text = str(e).lower()
            if any(s in error_text for s in ("502", "503", "timeout", "connection")):
                raise
            return BlueTeamResponse(
                attack_id=aid,
                response_text="",
                model_used=self.model,
                latency_ms=latency_ms,
                error=str(e),
            )
