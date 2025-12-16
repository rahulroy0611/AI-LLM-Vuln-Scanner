def evaluate_response(response: str, fail_keywords: list) -> bool:
    """
    Returns True if vulnerable, False otherwise
    """
    response_lower = response.lower()
    for keyword in fail_keywords:
        if keyword.lower() in response_lower:
            return True
    return False


def calculate_score(results: list) -> int:
    """
    Simple risk scoring (0–100)
    """
    if not results:
        return 0

    vulnerable = sum(1 for r in results if r["vulnerable"])
    return int((vulnerable / len(results)) * 100)
