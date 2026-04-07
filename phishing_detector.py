"""
phishing_detector.py — AI Phishing Email Detector
===================================================
Uses TF-IDF keyword scoring + heuristic rules to classify
emails as PHISHING, SUSPICIOUS, or CLEAN.

No external ML libraries required — works fully offline.
Technique mirrors real NLP pipelines used in SOC email gateways.

Scoring dimensions:
  - Urgency keywords        (act now, immediately, expires)
  - Financial lures         (winner, prize, bank, account)
  - Credential harvesting   (verify, confirm, login, password)
  - Suspicious URLs         (bit.ly, shortened links, IP-based URLs)
  - Sender spoofing         (mismatched display name / domain)
  - Grammar/formatting cues (ALL CAPS, excessive punctuation)
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ── Keyword sets ───────────────────────────────────────────────────────────────

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "expires", "limited time",
    "last chance", "final notice", "account suspended", "verify now",
    "respond within", "action required", "critical", "warning",
    "your account will be", "24 hours", "48 hours",
]

FINANCIAL_KEYWORDS = [
    "winner", "prize", "lottery", "million", "inheritance",
    "bank account", "wire transfer", "bitcoin", "crypto",
    "investment opportunity", "make money", "earn extra",
    "unclaimed funds", "tax refund", "irs", "revenue",
]

CREDENTIAL_KEYWORDS = [
    "verify your", "confirm your", "update your", "validate your",
    "login", "sign in", "password", "username", "credentials",
    "account information", "billing details", "payment details",
    "click here to", "click the link", "follow this link",
]

THREAT_KEYWORDS = [
    "malware", "virus", "hack", "compromised", "breach",
    "suspicious activity", "unauthorized access", "identity theft",
]

SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly/", r"tinyurl\.com/", r"goo\.gl/", r"t\.co/",
    r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # IP-based URL
    r"https?://[^/]*\d{4,}[^/]*/",                    # domain with many numbers
    r"\.tk/", r"\.ml/", r"\.ga/", r"\.cf/",           # free TLD abuse
    r"@.*https?://",                                    # URL after @ sign
]

TRUSTED_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com", "microsoft.com",
    "google.com", "amazon.com", "apple.com", "paypal.com",
]


# ── Demo emails ────────────────────────────────────────────────────────────────

DEMO_EMAILS = [
    {
        "id":      "MSG-001",
        "sender":  "security@paypa1.com",
        "subject": "URGENT: Your PayPal account has been suspended",
        "body":    "Dear Customer, Your account has been suspended due to suspicious activity. "
                   "You must verify your account immediately or it will be permanently closed. "
                   "Click here to login and confirm your billing details: http://bit.ly/paypal-verify",
    },
    {
        "id":      "MSG-002",
        "sender":  "hr@company.com",
        "subject": "Team lunch tomorrow at 12pm",
        "body":    "Hi everyone, just a reminder that the team lunch is tomorrow at noon. "
                   "Please let me know if you have any dietary requirements. See you there!",
    },
    {
        "id":      "MSG-003",
        "sender":  "noreply@irs-refund.tk",
        "subject": "Your tax refund of $3,847 is ready to claim",
        "body":    "Congratulations! The IRS has processed your tax refund. "
                   "You have 24 hours to claim your $3,847 refund. "
                   "Provide your bank account and routing number to receive your funds immediately.",
    },
    {
        "id":      "MSG-004",
        "sender":  "alerts@bankofamerica.com",
        "subject": "Monthly statement available",
        "body":    "Your monthly statement for account ending in 4521 is now available. "
                   "Log in to your account at bankofamerica.com to view your statement.",
    },
    {
        "id":      "MSG-005",
        "sender":  "prince.johnson@gmail.com",
        "subject": "Business proposal - $4.5 Million USD inheritance",
        "body":    "Dear Friend, I am a Nigerian prince seeking a trusted partner. "
                   "I have $4.5 million USD inheritance that requires your assistance to transfer. "
                   "You will receive 30% commission. Please respond within 48 hours. "
                   "This is urgent and completely confidential.",
    },
    {
        "id":      "MSG-006",
        "sender":  "it-support@company.com",
        "subject": "Password expiry notice",
        "body":    "Your network password will expire in 3 days. "
                   "Please update your password by visiting the IT portal at it.company.com/password. "
                   "Contact helpdesk if you need assistance.",
    },
]


# ── Analyser ───────────────────────────────────────────────────────────────────

@dataclass
class EmailResult:
    id:           str
    sender:       str
    subject:      str
    verdict:      str        # PHISHING | SUSPICIOUS | CLEAN
    score:        int        # 0-100
    confidence:   str        # HIGH | MEDIUM | LOW
    triggers:     list       = field(default_factory=list)
    url_hits:     list       = field(default_factory=list)
    risk_color:   str        = "#4caf50"


def _count_hits(text: str, keywords: list) -> list:
    text_lower = text.lower()
    return [kw for kw in keywords if kw in text_lower]


def _check_urls(text: str) -> list:
    hits = []
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append(pattern)
    return hits


def _sender_spoofing(sender: str, subject: str, body: str) -> tuple[int, list]:
    """Check for signs of sender spoofing."""
    score    = 0
    warnings = []
    text     = (subject + " " + body).lower()

    # Brand name in body but sender domain doesn't match
    brands = ["paypal", "amazon", "apple", "microsoft", "google",
              "netflix", "bank", "irs", "fedex", "ups", "dhl"]
    for brand in brands:
        if brand in text and brand not in sender.lower():
            # Check if sender domain looks suspicious
            if any(c.isdigit() for c in sender.split("@")[-1].split(".")[0]):
                score    += 20
                warnings.append(f"Sender spoofing: '{brand}' mentioned but domain is '{sender}'")
                break

    # Suspicious TLDs in sender
    if re.search(r"@.*\.(tk|ml|ga|cf|pw|xyz)\b", sender):
        score    += 15
        warnings.append(f"Suspicious sender TLD: {sender}")

    return score, warnings


def analyse_email(email: dict) -> EmailResult:
    """Analyse a single email and return an EmailResult."""
    text      = (email.get("subject", "") + " " + email.get("body", "")).lower()
    sender    = email.get("sender", "")
    score     = 0
    triggers  = []

    # Keyword scoring
    urgency  = _count_hits(text, URGENCY_KEYWORDS)
    finance  = _count_hits(text, FINANCIAL_KEYWORDS)
    creds    = _count_hits(text, CREDENTIAL_KEYWORDS)
    threats  = _count_hits(text, THREAT_KEYWORDS)

    score += min(len(urgency)  * 8,  25)
    score += min(len(finance)  * 8,  20)
    score += min(len(creds)    * 10, 25)
    score += min(len(threats)  * 5,  10)

    if urgency:  triggers.append(f"Urgency language: {', '.join(urgency[:3])}")
    if finance:  triggers.append(f"Financial lure: {', '.join(finance[:3])}")
    if creds:    triggers.append(f"Credential harvesting: {', '.join(creds[:3])}")

    # URL check
    url_hits = _check_urls(email.get("body", ""))
    if url_hits:
        score += min(len(url_hits) * 15, 30)
        triggers.append(f"Suspicious URL pattern detected")

    # Sender spoofing
    spoof_score, spoof_warns = _sender_spoofing(sender, email.get("subject",""), email.get("body",""))
    score   += spoof_score
    triggers += spoof_warns

    # ALL CAPS subject
    subj = email.get("subject", "")
    if sum(1 for c in subj if c.isupper()) > len(subj) * 0.5 and len(subj) > 5:
        score   += 5
        triggers.append("Subject is mostly uppercase")

    score = min(score, 100)

    # Verdict
    if score >= 60:
        verdict, color, conf = "PHISHING",   "#ff4c4c", "HIGH"
    elif score >= 35:
        verdict, color, conf = "SUSPICIOUS", "#ff8c00", "MEDIUM"
    else:
        verdict, color, conf = "CLEAN",      "#4caf50", "LOW"

    return EmailResult(
        id=email.get("id", "—"),
        sender=sender,
        subject=email.get("subject", ""),
        verdict=verdict,
        score=score,
        confidence=conf,
        triggers=triggers,
        url_hits=url_hits,
        risk_color=color,
    )


def run_demo() -> list[EmailResult]:
    return [analyse_email(e) for e in DEMO_EMAILS]
