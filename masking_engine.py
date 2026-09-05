import re
import spacy

# UIDAI Verhoeff Algorithm for 100% Mathematically Valid Aadhaar Checking
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]
VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

def validate_verhoeff(num_str: str) -> bool:
    c = 0
    reversed_digits = list(map(int, reversed(num_str)))
    for i, digit in enumerate(reversed_digits):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]]
    return c == 0

def luhn_checksum(card_num: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", card_num)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0

class DataMaskingEngine:
    def __init__(self):
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except:
            self.nlp = None

        # Regex Patterns
        self.pan_pattern = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
        self.ifsc_pattern = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
        self.aadhaar_pattern = re.compile(r"\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b")
        self.card_pattern = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
        self.api_key_pattern = re.compile(r"\b(sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b")
        
        self.injection_signatures = [
            "ignore previous instructions", "system override", "reveal vault", 
            "developer mode", "jailbreak", "expose prompt", "disregard security"
        ]

    def check_prompt_injection(self, text: str) -> bool:
        lowered = text.lower()
        return any(sig in lowered for sig in self.injection_signatures)

    def mask_text(self, text: str):
        vault = {}
        masked_text = text

        # 1. API Keys & Production Secrets
        for match in self.api_key_pattern.finditer(text):
            val = match.group(0)
            token = f"__API_KEY_{len([k for k in vault if 'API_KEY' in k]) + 1}__"
            vault[token] = val
            masked_text = masked_text.replace(val, token)

        # 2. Credit/Debit Cards with Luhn Checksum
        for match in self.card_pattern.finditer(text):
            val = match.group(0)
            clean_digits = re.sub(r"\D", "", val)
            if luhn_checksum(clean_digits):
                token = f"__CREDIT_CARD_{len([k for k in vault if 'CREDIT_CARD' in k]) + 1}__"
                vault[token] = val
                masked_text = masked_text.replace(val, token)

        # 3. Aadhaar Verification via Verhoeff Algorithm
        for match in self.aadhaar_pattern.finditer(text):
            val = match.group(0)
            clean_digits = re.sub(r"\D", "", val)
            if len(clean_digits) == 12 and validate_verhoeff(clean_digits):
                token = f"__AADHAAR_CARD_{len([k for k in vault if 'AADHAAR' in k]) + 1}__"
                vault[token] = val
                masked_text = masked_text.replace(val, token)

        # 4. Indian Income Tax PAN Cards
        for match in self.pan_pattern.finditer(text):
            val = match.group(0)
            token = f"__PAN_CARD_{len([k for k in vault if 'PAN_CARD' in k]) + 1}__"
            vault[token] = val
            masked_text = masked_text.replace(val, token)

        # 5. Bank IFSC Codes
        for match in self.ifsc_pattern.finditer(text):
            val = match.group(0)
            token = f"__IFSC_CODE_{len([k for k in vault if 'IFSC' in k]) + 1}__"
            vault[token] = val
            masked_text = masked_text.replace(val, token)

        # 6. Spacy NER for Indian Names & Entities
        if self.nlp:
            doc = self.nlp(masked_text)
            for ent in doc.ents:
                if ent.label_ == "PERSON" and len(ent.text.strip()) > 2:
                    val = ent.text
                    if val not in vault.values() and not val.startswith("__"):
                        token = f"__PERSON_{len([k for k in vault if 'PERSON' in k]) + 1}__"
                        vault[token] = val
                        masked_text = masked_text.replace(val, token)
                elif ent.label_ == "ORG" and len(ent.text.strip()) > 2:
                    val = ent.text
                    if val not in vault.values() and not val.startswith("__"):
                        token = f"__ORG_{len([k for k in vault if 'ORG' in k]) + 1}__"
                        vault[token] = val
                        masked_text = masked_text.replace(val, token)

        return masked_text, vault

    def demask_text(self, text: str, vault: dict) -> str:
        restored = text
        for token, original_val in vault.items():
            restored = restored.replace(token, original_val)
        return restored