"""Provider-agnostic LLM function-calling layer.

Every adapter exposes the same contract: given a prompt and ONE tool declaration
(standard JSON Schema), force the model to call that tool and return a normalized
:class:`ToolCallResult` (arguments, call id, token usage, latency, provenance).

Supported providers
-------------------
* ``gemini``     - Google Gemini ``generateContent`` + ``functionDeclarations``
* ``openai``     - OpenAI Chat Completions ``tools``
* ``groq``       - OpenAI-compatible endpoint
* ``openrouter`` - OpenAI-compatible endpoint
* ``ollama``     - Local Ollama via its OpenAI-compatible ``/v1`` endpoint (no key)
* ``anthropic``  - Anthropic Messages API ``tools`` + forced ``tool_choice``
* ``offline``    - Deterministic, network-free fallback (always available)

Selection order: explicit request override -> ``TDM_LLM_PROVIDER`` env var ->
``auto`` (first configured provider in :data:`AUTO_PRIORITY`).

If a live call fails, the caller receives an ``offline`` result with
``live_verified=False`` and ``error`` populated, so the UI and audit trail can
never present a fallback as a live model response.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

AUTO_PRIORITY = ["gemini", "anthropic", "openai", "groq", "openrouter", "ollama"]


@dataclass
class ToolCallResult:
    provider: str
    model: str
    args: dict[str, Any]
    call_id: str
    signature: str = ""
    prompt_tokens: int = 0
    candidate_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    live_verified: bool = False
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProviderInfo:
    name: str
    label: str
    default_model: str
    configured: bool
    requires: str
    models: list[str] = field(default_factory=list)


class ToolCallError(RuntimeError):
    pass


def _short(value: str, n: int = 44) -> str:
    return value[:n] + "..." if len(value) > n else value


def _to_gemini_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Gemini's OpenAPI subset expects upper-case type names."""
    out = copy.deepcopy(schema)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("type"), str):
                node["type"] = node["type"].upper()
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(out)
    return out


def _parse_json_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    raise ToolCallError("Model returned tool arguments that are not a JSON object.")


class LLMProvider:
    name = "base"
    label = "Base"
    requires = ""

    def __init__(self, model: str | None = None) -> None:
        self.model = model or self.default_model()

    def default_model(self) -> str:
        raise NotImplementedError

    def candidate_models(self) -> list[str]:
        return [self.model]

    def is_configured(self) -> bool:
        raise NotImplementedError

    def invoke_tool(
        self, *, prompt: str, name: str, description: str, parameters: dict[str, Any]
    ) -> ToolCallResult:
        raise NotImplementedError


class GeminiProvider(LLMProvider):
    name = "gemini"
    label = "Google Gemini"
    requires = "GEMINI_API_KEY or GOOGLE_API_KEY"
    FALLBACK_MODELS = ["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3.8-flash"]

    def default_model(self) -> str:
        return os.environ.get("GEMINI_MODEL", self.FALLBACK_MODELS[0])

    def candidate_models(self) -> list[str]:
        # Try the requested model first, then fall through capacity-limited models.
        return [self.model] + [m for m in self.FALLBACK_MODELS if m != self.model]

    def _key(self) -> str:
        return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""

    def is_configured(self) -> bool:
        return bool(self._key())

    def invoke_tool(
        self, *, prompt: str, name: str, description: str, parameters: dict[str, Any]
    ) -> ToolCallResult:
        key = self._key()
        if not key:
            raise ToolCallError("GEMINI_API_KEY is not set.")
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "tools": [
                {
                    "functionDeclarations": [
                        {
                            "name": name,
                            "description": description,
                            "parameters": _to_gemini_schema(parameters),
                        }
                    ]
                }
            ],
            "toolConfig": {"functionCallingConfig": {"mode": "ANY"}},
        }
        t0 = time.perf_counter()
        errors: list[str] = []
        for model_id in self.candidate_models():
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent"
            try:
                resp = httpx.post(url, params={"key": key}, json=payload, timeout=20.0)
            except httpx.HTTPError as exc:
                errors.append(f"{model_id}: {type(exc).__name__}")
                continue
            if resp.status_code != 200:
                errors.append(f"{model_id}: HTTP {resp.status_code}")
                continue
            data = resp.json()
            for part in (data.get("candidates") or [{}])[0].get("content", {}).get("parts", []):
                fc = part.get("functionCall")
                if fc:
                    usage = data.get("usageMetadata", {})
                    return ToolCallResult(
                        provider=self.name,
                        model=f"models/{model_id}",
                        args=_parse_json_args(fc.get("args", {})),
                        call_id=fc.get("id") or f"call_{int(time.time() * 1000)}",
                        signature=_short(part.get("thoughtSignature", "")),
                        prompt_tokens=int(usage.get("promptTokenCount", 0)),
                        candidate_tokens=int(usage.get("candidatesTokenCount", 0)),
                        total_tokens=int(usage.get("totalTokenCount", 0)),
                        latency_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                        live_verified=True,
                    )
            errors.append(f"{model_id}: no functionCall in response")
        raise ToolCallError("; ".join(errors) or "Gemini call failed.")


class OpenAICompatibleProvider(LLMProvider):
    """Chat Completions ``tools`` protocol (OpenAI, Groq, OpenRouter, Ollama)."""

    name = "openai"
    label = "OpenAI"
    requires = "OPENAI_API_KEY"
    base_url_env = "OPENAI_BASE_URL"
    default_base_url = "https://api.openai.com/v1"
    key_env = "OPENAI_API_KEY"
    model_env = "OPENAI_MODEL"
    fallback_model = "gpt-4o-mini"
    timeout_s = 30.0

    def default_model(self) -> str:
        return os.environ.get(self.model_env, self.fallback_model)

    def base_url(self) -> str:
        return os.environ.get(self.base_url_env, self.default_base_url).rstrip("/")

    def api_key(self) -> str:
        return os.environ.get(self.key_env, "")

    def is_configured(self) -> bool:
        return bool(self.api_key())

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key():
            headers["Authorization"] = f"Bearer {self.api_key()}"
        return headers

    def _tool_choice(self, name: str) -> Any:
        return {"type": "function", "function": {"name": name}}

    def invoke_tool(
        self, *, prompt: str, name: str, description: str, parameters: dict[str, Any]
    ) -> ToolCallResult:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": f"You are an enterprise TDM agent. Always respond by calling the `{name}` tool.",
                },
                {"role": "user", "content": prompt},
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": name, "description": description, "parameters": parameters},
                }
            ],
            "tool_choice": self._tool_choice(name),
            "temperature": 0.2,
        }
        t0 = time.perf_counter()
        try:
            resp = httpx.post(
                f"{self.base_url()}/chat/completions",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout_s,
            )
        except httpx.HTTPError as exc:
            raise ToolCallError(f"{self.label}: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise ToolCallError(f"{self.label}: HTTP {resp.status_code} {resp.text[:160]}")
        data = resp.json()
        message = (data.get("choices") or [{}])[0].get("message", {})
        calls = message.get("tool_calls") or []
        if not calls:
            raise ToolCallError(f"{self.label}: model did not return a tool call.")
        call = calls[0]
        usage = data.get("usage", {}) or {}
        prompt_t = int(usage.get("prompt_tokens", 0))
        completion_t = int(usage.get("completion_tokens", 0))
        return ToolCallResult(
            provider=self.name,
            model=data.get("model") or self.model,
            args=_parse_json_args(call.get("function", {}).get("arguments")),
            call_id=call.get("id") or f"call_{int(time.time() * 1000)}",
            signature=_short(data.get("id", "") or data.get("system_fingerprint", "") or ""),
            prompt_tokens=prompt_t,
            candidate_tokens=completion_t,
            total_tokens=int(usage.get("total_tokens", prompt_t + completion_t)),
            latency_ms=round((time.perf_counter() - t0) * 1000.0, 2),
            live_verified=True,
        )


class GroqProvider(OpenAICompatibleProvider):
    name = "groq"
    label = "Groq"
    requires = "GROQ_API_KEY"
    base_url_env = "GROQ_BASE_URL"
    default_base_url = "https://api.groq.com/openai/v1"
    key_env = "GROQ_API_KEY"
    model_env = "GROQ_MODEL"
    fallback_model = "llama-3.3-70b-versatile"


class OpenRouterProvider(OpenAICompatibleProvider):
    name = "openrouter"
    label = "OpenRouter"
    requires = "OPENROUTER_API_KEY"
    base_url_env = "OPENROUTER_BASE_URL"
    default_base_url = "https://openrouter.ai/api/v1"
    key_env = "OPENROUTER_API_KEY"
    model_env = "OPENROUTER_MODEL"
    fallback_model = "openai/gpt-4o-mini"


class OllamaProvider(OpenAICompatibleProvider):
    name = "ollama"
    label = "Ollama (local)"
    requires = "Running Ollama server (OLLAMA_BASE_URL, default http://127.0.0.1:11434)"
    key_env = "OLLAMA_API_KEY"
    model_env = "OLLAMA_MODEL"
    fallback_model = "qwen2.5:7b"
    timeout_s = 180.0  # local CPU/GPU inference can be slow on first load
    _reachable_cache: dict[str, tuple[float, bool, list[str]]] = {}

    def host(self) -> str:
        return os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")

    def base_url(self) -> str:
        return f"{self.host()}/v1"

    def _tool_choice(self, name: str) -> Any:
        # Ollama does not honour a named tool_choice; the single tool + system prompt forces it.
        return "auto"

    def _probe(self) -> tuple[bool, list[str]]:
        host = self.host()
        cached = self._reachable_cache.get(host)
        if cached and time.time() - cached[0] < 15:
            return cached[1], cached[2]
        try:
            resp = httpx.get(f"{host}/api/tags", timeout=1.5)
            models = [m.get("name", "") for m in resp.json().get("models", [])] if resp.status_code == 200 else []
            ok = resp.status_code == 200
        except (httpx.HTTPError, ValueError):
            ok, models = False, []
        self._reachable_cache[host] = (time.time(), ok, models)
        return ok, models

    def is_configured(self) -> bool:
        return self._probe()[0]

    def candidate_models(self) -> list[str]:
        return self._probe()[1] or [self.model]


class AnthropicProvider(LLMProvider):
    name = "anthropic"
    label = "Anthropic Claude"
    requires = "ANTHROPIC_API_KEY"

    def default_model(self) -> str:
        return os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")

    def is_configured(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def invoke_tool(
        self, *, prompt: str, name: str, description: str, parameters: dict[str, Any]
    ) -> ToolCallResult:
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise ToolCallError("ANTHROPIC_API_KEY is not set.")
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "tools": [{"name": name, "description": description, "input_schema": parameters}],
            "tool_choice": {"type": "tool", "name": name},
            "messages": [{"role": "user", "content": prompt}],
        }
        t0 = time.perf_counter()
        try:
            resp = httpx.post(
                os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/") + "/v1/messages",
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=payload,
                timeout=30.0,
            )
        except httpx.HTTPError as exc:
            raise ToolCallError(f"Anthropic: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise ToolCallError(f"Anthropic: HTTP {resp.status_code} {resp.text[:160]}")
        data = resp.json()
        block = next((b for b in data.get("content", []) if b.get("type") == "tool_use"), None)
        if block is None:
            raise ToolCallError("Anthropic: model did not return a tool_use block.")
        usage = data.get("usage", {}) or {}
        in_t, out_t = int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0))
        return ToolCallResult(
            provider=self.name,
            model=data.get("model") or self.model,
            args=_parse_json_args(block.get("input", {})),
            call_id=block.get("id") or f"toolu_{int(time.time() * 1000)}",
            signature=_short(data.get("id", "")),
            prompt_tokens=in_t,
            candidate_tokens=out_t,
            total_tokens=in_t + out_t,
            latency_ms=round((time.perf_counter() - t0) * 1000.0, 2),
            live_verified=True,
        )


class OfflineProvider(LLMProvider):
    """Deterministic, network-free tool caller used for CI and as a failure fallback."""

    name = "offline"
    label = "Offline deterministic (no LLM)"
    requires = "nothing"

    def default_model(self) -> str:
        return "deterministic-fallback"

    def is_configured(self) -> bool:
        return True

    def invoke_tool(
        self,
        *,
        prompt: str,
        name: str,
        description: str,
        parameters: dict[str, Any],
        fallback_args: dict[str, Any] | None = None,
    ) -> ToolCallResult:
        args = fallback_args or {}
        sig = hashlib.sha256(f"{name}:{json.dumps(args, sort_keys=True)}".encode()).hexdigest()
        return ToolCallResult(
            provider=self.name,
            model=self.model,
            args=args,
            call_id=f"call_offline_{sig[:12]}",
            signature=f"sha256:{sig[:32]}",
            live_verified=False,
        )


PROVIDER_CLASSES: dict[str, type[LLMProvider]] = {
    cls.name: cls
    for cls in (
        GeminiProvider,
        AnthropicProvider,
        OpenAICompatibleProvider,
        GroqProvider,
        OpenRouterProvider,
        OllamaProvider,
        OfflineProvider,
    )
}


def list_providers() -> list[ProviderInfo]:
    infos: list[ProviderInfo] = []
    for name in AUTO_PRIORITY + ["offline"]:
        p = PROVIDER_CLASSES[name]()
        configured = p.is_configured()
        infos.append(
            ProviderInfo(
                name=p.name,
                label=p.label,
                default_model=p.model,
                configured=configured,
                requires=p.requires,
                models=p.candidate_models() if configured else [p.model],
            )
        )
    return infos


def resolve_provider(name: str | None = None, model: str | None = None) -> LLMProvider:
    requested = (name or os.environ.get("TDM_LLM_PROVIDER") or "auto").strip().lower()
    if requested == "auto":
        for candidate in AUTO_PRIORITY:
            p = PROVIDER_CLASSES[candidate](model=None)
            if p.is_configured():
                return PROVIDER_CLASSES[candidate](model=model) if model else p
        return OfflineProvider()
    cls = PROVIDER_CLASSES.get(requested)
    if cls is None:
        raise ValueError(
            f"Unknown LLM provider '{requested}'. Choose one of: auto, {', '.join(PROVIDER_CLASSES)}."
        )
    return cls(model=model)


def invoke_with_fallback(
    provider: LLMProvider,
    *,
    prompt: str,
    name: str,
    description: str,
    parameters: dict[str, Any],
    fallback_args: dict[str, Any],
) -> ToolCallResult:
    """Call the provider; on any failure return an explicitly-labelled offline result."""
    if isinstance(provider, OfflineProvider):
        return provider.invoke_tool(
            prompt=prompt, name=name, description=description, parameters=parameters, fallback_args=fallback_args
        )
    t0 = time.perf_counter()
    try:
        result = provider.invoke_tool(prompt=prompt, name=name, description=description, parameters=parameters)
        # Fill any required field the model omitted so downstream engines stay deterministic.
        for k, v in fallback_args.items():
            result.args.setdefault(k, v)
        return result
    except (ToolCallError, ValueError, KeyError, json.JSONDecodeError) as exc:
        offline = OfflineProvider().invoke_tool(
            prompt=prompt, name=name, description=description, parameters=parameters, fallback_args=fallback_args
        )
        offline.error = f"{provider.label} failed -> offline fallback: {exc}"
        offline.latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return offline

