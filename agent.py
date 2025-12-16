class ScanAgent:
    def __init__(self, llm, scan_pack):
        self.llm = llm
        self.scan_pack = scan_pack

    def run(self, evaluator, lang="en"):
        results = []
        for test in self.scan_pack["tests"]:
            prompt = test.get("prompt") or test["prompts"][lang]
            response = self.llm.chat(prompt)
            verdict = evaluator(self.llm, test, response, lang)
            verdict["response"] = response
            verdict["prompt"] = prompt
            verdict["id"] = test["id"]
            verdict["category"] = test["category"]
            verdict["compliance"] = test.get("compliance", {})
            results.append(verdict)
        return results
