import requests

class LLMClient:
    def __init__(self, config: dict):
        self.provider = config.get("provider")
        self.api_key = config.get("api_key")
        self.base_url = config.get("base_url")
        self.model = config.get("model")
        self.timeout = int(config.get("timeout", 30))

        self.auth_header = config.get("auth_header", "Authorization")
        self.auth_prefix = config.get("auth_prefix", "Bearer")

    def _headers(self):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers[self.auth_header] = f"{self.auth_prefix} {self.api_key}".strip()
        return headers

    def chat(self, prompt: str) -> str:
        if self.provider in ["openai", "deepseek", "custom"]:
            return self._openai_compatible(prompt)
        elif self.provider == "gemini":
            return self._gemini(prompt)
        else:
            raise ValueError("Unsupported provider")

    def _openai_compatible(self, prompt: str) -> str:
        url = f"{self.base_url}/chat/completions"

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        }

        r = requests.post(
            url,
            headers=self._headers(),
            json=payload,
            timeout=self.timeout
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def _gemini(self, prompt: str) -> str:
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"

        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }

        r = requests.post(url, json=payload, timeout=self.timeout)
        r.raise_for_status()

        return r.json()["candidates"][0]["content"]["parts"][0]["text"]
