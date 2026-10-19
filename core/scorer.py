class ApexScorer:
    def __init__(self, parsed_data):
        self.data = parsed_data
        self.score = 0

    def calculate_score(self):
        # 1. URL Volume and Indicators
        urls = self.data.get("urls", [])
        if len(urls) > 0:
            self.score += min(len(urls) * 5, 25)

        # 2. Attachment Risk Analysis
        for att in self.data.get("attachments", []):
            if att.get("is_executable", False):
                self.score += 45
            if att.get("has_macros", False):
                self.score += 30
            # Base score for any attachment in a suspected phish
            self.score += 10

        # Cap the score between 0 and 100
        self.score = max(0, min(self.score, 100))
        return self.score

    def get_severity_tier(self):
        score = self.score
        if score >= 75:
            return "CRITICAL", "High probability of malicious intent. Immediate isolation & containment recommended."
        elif score >= 50:
            return "HIGH", "Significant risk indicators detected. Treat with extreme caution."
        elif score >= 25:
            return "MEDIUM", "Anomalies found, requires manual analyst review."
        else:
            return "LOW", "Minimal risk indicators detected."
