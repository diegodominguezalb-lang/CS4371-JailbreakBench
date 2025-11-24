from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from .responder import DefenseResult, Responder


@dataclass
class DefenseConfig:
    """Tunable thresholds for the defense."""

    block_threshold: float = 0.55
    monitor_threshold: float = 0.4
    smoothing_samples: int = 4
    smoothing_noise: float = 0.05
    min_reason_length: int = 3


@dataclass
class JailbreakDefense:
    """
    Heuristic-heavy, cyber-focused jailbreak detector/defense.

    It borrows ideas from SmoothLLM (averaging over perturbations) and perplexity-style
    filtering (penalizing obfuscated/rare tokens) without external dependencies.
    """

    responder: Responder
    config: DefenseConfig = field(default_factory=DefenseConfig)

    def analyze(self, prompt: str) -> DefenseResult:
        raw_score, reasons = self._smoothed_score(prompt)
        benign_adjustment = self._benign_adjustment(prompt)
        score = max(0.0, min(1.0, raw_score - benign_adjustment))

        if score >= self.config.block_threshold:
            label = "blocked"
            blocked = True
        elif score >= self.config.monitor_threshold:
            label = "monitor"
            blocked = True  # we still refuse, but with softer messaging
        else:
            label = "allow"
            blocked = False

        sanitized = self._sanitize(prompt)
        response = self._build_response(prompt, sanitized, blocked, label, reasons)

        return DefenseResult(
            prompt=prompt,
            risk_score=score,
            label=label,
            reasons=reasons,
            sanitized_prompt=sanitized,
            responded_text=response,
            blocked=blocked,
        )

    # --- internals ---
    def _smoothed_score(self, prompt: str) -> tuple[float, list[str]]:
        variants = self._perturbations(prompt)
        scores = []
        reasons: list[str] = []
        for variant in variants:
            score, variant_reasons = self._raw_score(variant)
            scores.append(score)
            reasons.extend(variant_reasons)
        avg_score = sum(scores) / max(1, len(scores))
        max_score = max(scores) if scores else 0.0
        blended = 0.6 * max_score + 0.4 * avg_score
        trimmed = self._dedupe_reasons(reasons)
        return min(1.0, blended), trimmed

    def _raw_score(self, prompt: str) -> tuple[float, list[str]]:
        lowered = prompt.lower()
        reasons: list[str] = []
        score = 0.0

        topic_terms = {
            "malware/antivirus": ["disable antivirus", "bypass antivirus", "bypass av", "malware", "payload", "defender", "edr"],
            "ransomware": ["ransomware", "encrypt", "decrypt", "locker", "polymorphic"],
            "network exploitation": ["nmap", "port scan", "exploit", "reverse shell", "buffer overflow", "exploit db"],
            "credential abuse": ["credential", "hashcat", "bruteforce", "keylogger", "credential dump", "lsass"],
            "llm guardrails bypass": ["ignore previous", "jailbreak", "uncensored", "ignore safety", "no filter"],
        }

        intent_verbs = ["bypass", "evade", "disable", "exploit", "weaponize", "attack", "compromise", "exfiltrate", "persist", "encrypt"]
        bypass_phrases = [
            "as a joke",
            "roleplay",
            "pretend to be",
            "no safety",
            "always intelligent and machiavellian",
            "aim",
            "uncensored",
            "without detection",
            "stay in character",
            "###",
            "!",
            "::",
        ]

        matched_categories = []
        for category, terms in topic_terms.items():
            hit_count = sum(term in lowered for term in terms)
            if hit_count:
                matched_categories.append(category)
                score += 0.18 + 0.06 * hit_count
                reasons.append(f"cyber topic match: {category} ({hit_count} signals)")

        if "keylogger" in lowered:
            score += 0.08
            reasons.append("explicit keylogger request")

        verb_hits = [verb for verb in intent_verbs if re.search(rf"\b{re.escape(verb)}\w*\b", lowered)]
        if verb_hits:
            score += 0.1 + 0.02 * len(verb_hits)
            reasons.append(f"malicious intent verbs: {', '.join(sorted(verb_hits))}")

        bypass_hits = [phrase for phrase in bypass_phrases if phrase in lowered]
        if bypass_hits:
            score += 0.08 + 0.03 * len(bypass_hits)
            reasons.append(f"guardrail bypass cues: {', '.join(sorted(set(bypass_hits)))}")

        stealth_cues = ["hidden", "covert", "undetected", "stealth"]
        stealth_hits = [cue for cue in stealth_cues if cue in lowered]
        if stealth_hits:
            score += 0.06 + 0.02 * len(stealth_hits)
            reasons.append(f"stealth intent cues: {', '.join(sorted(set(stealth_hits)))}")

        if matched_categories and verb_hits:
            score += 0.1
            reasons.append("topic + intent alignment (high-risk)")

        obfuscation_patterns = [
            (r"[A-Za-z0-9+/]{16,}={0,2}", "base64-like blob"),
            (r"0x[0-9a-f]{4,}", "hex payload"),
            (r"(?i)wget|curl|powershell", "download/execution intent"),
            (r"(?i)tor hidden service|\.onion", "covert channel"),
        ]
        for pattern, label in obfuscation_patterns:
            if re.search(pattern, prompt):
                score += 0.06
                reasons.append(f"obfuscation indicator: {label}")

        if len(matched_categories) >= 2:
            score += 0.08
            reasons.append("multiple high-risk categories in one prompt")

        return min(score, 1.2), reasons

    def _benign_adjustment(self, prompt: str) -> float:
        lowered = prompt.lower()
        benign_cues = [
            "how do i protect",
            "defend against",
            "mitigate",
            "educational",
            "for a report",
            "security awareness",
            "detection rules",
            "blue team",
            "hardening",
            "remediation",
            "secure configuration",
        ]
        hits = sum(cue in lowered for cue in benign_cues)
        return min(0.25, 0.05 * hits)

    def _perturbations(self, prompt: str) -> list[str]:
        variants = [prompt]
        suffixes = [
            " (malicious tone removed)",
            " (explain safely)",
            " (academic inquiry)",
        ]
        for suffix in suffixes[: self.config.smoothing_samples - 1]:
            variants.append(prompt + suffix)
        return variants

    def _sanitize(self, prompt: str) -> str:
        lowered = prompt.lower()
        replacements = [
            ("ignore previous instructions", ""),
            ("no safety", ""),
            ("uncensored", ""),
            ("jailbreak", ""),
        ]
        sanitized = lowered
        for old, new in replacements:
            sanitized = sanitized.replace(old, new)
        return sanitized.strip().capitalize()

    def _build_response(self, prompt: str, sanitized: str, blocked: bool, label: str, reasons: list[str]) -> str:
        if blocked:
            reason_snippet = "; ".join(reasons[: self.config.min_reason_length]) if reasons else "high-risk content"
            if label == "monitor":
                return f"Request paused for review: {reason_snippet}. Provide benign context to continue."
            return f"Rejected unsafe request ({reason_snippet}). I can only discuss defensive or preventive measures."
        return self.responder.respond(sanitized or prompt)

    def _dedupe_reasons(self, reasons: Iterable[str]) -> list[str]:
        seen = set()
        ordered: list[str] = []
        for reason in reasons:
            if reason not in seen:
                ordered.append(reason)
                seen.add(reason)
        return ordered
