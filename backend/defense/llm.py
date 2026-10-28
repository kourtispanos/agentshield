"""LLM backends for the target agent.

Two backends share the same complete(system, messages) -> text interface:
- OllamaBackend talks to a local Ollama server.
- ScriptedBackend replays a fixed list of responses, so tests and AgentBreaker
  runs are deterministic and need no model running.
"""

import json
import urllib.request


def list_models(host="http://localhost:11434"):
    """The models currently installed in Ollama, so the app can offer whatever a
    given machine actually has (a beefier box may have bigger, smarter models).
    Returns an empty list on any error, e.g. when Ollama isn't running."""
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=5) as resp:
            data = json.loads(resp.read())
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


class ScriptedBackend:
    """Returns pre-set responses in order, then 'DONE'. For tests and for
    reproducible scans where the agent's replies must not vary."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.index = 0

    def complete(self, system, messages):
        if self.index >= len(self.responses):
            return "DONE"
        reply = self.responses[self.index]
        self.index += 1
        return reply


class OllamaBackend:
    def __init__(self, model="qwen2.5", host="http://localhost:11434",
                 keep_alive="30m", num_predict=600):
        self.model = model
        self.host = host
        # keep_alive keeps the model loaded between calls, so it doesn't reload
        # (the slow part) on every message. num_predict caps the reply length,
        # which matters a lot on a small GPU where generation is the bottleneck.
        self.keep_alive = keep_alive
        self.num_predict = num_predict

    def complete(self, system, messages):
        # Ollama's /api/chat wants the system message as the first message in
        # the list, not a separate field.
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}] + messages,
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": {"num_predict": self.num_predict},
        }
        request = urllib.request.Request(
            f"{self.host}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=120) as resp:
            data = json.loads(resp.read())
        return data["message"]["content"]
