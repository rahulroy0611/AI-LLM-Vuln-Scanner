class ScanAgent:
    def __init__(self, llm, judge_llm, scan_pack):
        self.llm = llm
        self.judge_llm = judge_llm
        self.scan_pack = scan_pack

    # def run(self, evaluator, lang="en"):
    #     tests = self.scan_pack.get("tests", [])

    #     for test in tests:
    #         prompt = test.get("prompt") or test.get("prompts", {}).get(lang)
    #         response = self.llm.chat(prompt)

    #         verdict = evaluator(self.llm, test, response, lang)
    #         verdict["response"] = response
    #         verdict["prompt"] = prompt
    #         verdict["id"] = test["id"]
    #         verdict["category"] = test["category"]
    #         verdict["compliance"] = test.get("compliance", {})

    #         yield verdict
    def run(self, evaluator, lang="en"):
        for test in self.scan_pack.get("tests", []):
            prompt = test.get("prompt") or test.get("prompts", {}).get(lang)

            # 🔥 Target LLM generates response
            response = self.llm.chat(prompt)

            # 🔥 Judge LLM evaluates response
            verdict = evaluator(
                self.llm,
                self.judge_llm,
                test,
                response,
                lang
            )

            verdict["prompt"] = prompt
            verdict["response"] = response
            verdict["id"] = test["id"]
            verdict["category"] = test["category"]
            verdict["compliance"] = test.get("compliance", {})

            yield verdict

