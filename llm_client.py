import requests

class LLMClient:
    def __init__(self, config):
        self.provider = config["provider"]
        self.base_url = config["base_url"]
        self.model = config["model"]
        self.api_key = config.get("api_key", "")
        self.timeout = config.get("timeout", 60)
        self.auth_header = config.get("auth_header", "Authorization")
        self.auth_prefix = config.get("auth_prefix", "Bearer")

    def _headers(self):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers[self.auth_header] = f"{self.auth_prefix} {self.api_key}".strip()
        return headers

    def chat(self, prompt):
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0
        }
        r = requests.post(url, json=payload, headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
