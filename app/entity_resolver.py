# Cross-Document Entity Resolution Engine
import re
import unicodedata
from typing import List, Tuple, Dict, Any, Optional
from app.models import EntityMatchResult, EntityMatchExplanation

# Common Devanagari to Latin phonetic transliteration map
DEVANAGARI_LATIN_MAP = {
    'रा': 'ra', 'जे': 'je', 'श': 'sh', 'क': 'ku', 'मा': 'ma', 'र': 'r',
    'श': 'sh', 'र्': 'r', 'मा': 'ma', 'राजेश': 'rajesh', 'कुमार': 'kumar',
    'शर्मा': 'sharma', 'सिंह': 'singh', 'वर्मा': 'verma', 'गुप्ता': 'gupta',
    'अ': 'a', 'आ': 'aa', 'इ': 'i', 'ई': 'ee', 'उ': 'u', 'ऊ': 'oo',
    'क': 'k', 'ख': 'kh', 'ग': 'g', 'घ': 'gh', 'च': 'ch', 'छ': 'chh',
    'ज': 'j', 'झ': 'jh', 'ट': 't', 'ठ': 'th', 'ड': 'd', 'ढ': 'dh',
    'त': 't', 'थ': 'th', 'द': 'd', 'ध': 'dh', 'न': 'n', 'प': 'p',
    'फ': 'ph', 'ब': 'b', 'भ': 'bh', 'म': 'm', 'य': 'y', 'र': 'r',
    'ल': 'l', 'व': 'v', 'श': 'sh', 'ष': 'sh', 'स': 's', 'ह': 'h'
}

HONORIFICS = {"mr", "mrs", "ms", "dr", "er", "prof", "shri", "smt", "kumari", "shree"}

class EntityResolver:
    """
    Resolves entity discrepancies across documents without auto-merging.
    Accounts for initials expansion, cross-script transliteration, token ordering, and honorifics.
    """

    @classmethod
    def strip_honorifics(cls, name: str) -> Tuple[str, Optional[str]]:
        tokens = re.split(r"[\s\.,]+", name.strip())
        removed = None
        cleaned_tokens = []
        for t in tokens:
            if not t:
                continue
            if t.lower() in HONORIFICS and removed is None:
                removed = t
            else:
                cleaned_tokens.append(t)
        return " ".join(cleaned_tokens), removed

    @classmethod
    def transliterate_devanagari(cls, text: str) -> str:
        """Translates Devanagari script tokens to Latin approximation."""
        result = text
        # Whole word replacements first
        for dev, lat in DEVANAGARI_LATIN_MAP.items():
            if len(dev) > 1 and dev in result:
                result = result.replace(dev, lat)
        # Char-by-char fallback
        chars = []
        for ch in result:
            chars.append(DEVANAGARI_LATIN_MAP.get(ch, ch))
        cleaned = "".join(chars).lower()
        return re.sub(r"[^a-z0-9\s]", "", cleaned)

    @classmethod
    def normalize_tokens(cls, text: str) -> List[str]:
        cleaned = text.lower().replace(",", " ").replace(".", " ")
        return [tok.strip() for tok in cleaned.split() if tok.strip()]

    @classmethod
    def check_initials_expansion(cls, tokens_a: List[str], tokens_b: List[str]) -> Tuple[bool, float, str]:
        """
        Tests if one token list is an initials abbreviation of the other.
        e.g. ['r', 'k', 'sharma'] vs ['rajesh', 'kumar', 'sharma']
        """
        if len(tokens_a) != len(tokens_b):
            return False, 0.0, ""

        matches = 0
        expansions = 0
        details = []

        for ta, tb in zip(tokens_a, tokens_b):
            if ta == tb:
                matches += 1
            elif (len(ta) == 1 and tb.startswith(ta)) or (len(tb) == 1 and ta.startswith(tb)):
                expansions += 1
                details.append(f"Initial '{ta if len(ta)==1 else tb}.' matches expansion '{tb if len(ta)==1 else ta}'")
            else:
                return False, 0.0, ""

        if expansions > 0:
            score = 55.0 + (matches * 20.0)
            return True, min(score, 80.0), "; ".join(details)
        return False, 0.0, ""

    @classmethod
    def check_token_permutation(cls, tokens_a: List[str], tokens_b: List[str]) -> Tuple[bool, float, str]:
        """
        Tests if names match under permutation (e.g. Last Name, First Name).
        e.g. ['sharma', 'rajesh', 'kumar'] vs ['rajesh', 'kumar', 'sharma']
        """
        set_a = set(tokens_a)
        set_b = set(tokens_b)
        if len(tokens_a) == len(tokens_b) and set_a == set_b and tokens_a != tokens_b:
            return True, 40.0, f"Token permutation detected: ordering difference between '{' '.join(tokens_a)}' and '{' '.join(tokens_b)}'"
        return False, 0.0, ""

    @classmethod
    def resolve_names(cls, name_a: str, name_b: str, rank: int = 1) -> EntityMatchResult:
        """
        Compares two person names across scripts, formats, and conventions.
        Returns detailed match score and ranked breakdown.
        STRICT GUARANTEE: Never auto-merges records (auto_merged = False).
        """
        explanations: List[EntityMatchExplanation] = []
        confidence = 0.0

        # Exact match check
        if name_a.strip().lower() == name_b.strip().lower():
            explanations.append(EntityMatchExplanation(
                factor="EXACT_MATCH",
                description="Identical character sequence match.",
                score_impact=100.0
            ))
            return EntityMatchResult(
                entity_a_value=name_a,
                entity_b_value=name_b,
                entity_type="PERSON_NAME",
                overall_confidence=100.0,
                rank=rank,
                ranked_explanations=explanations,
                match_tier="HIGH_CONFIDENCE_MATCH",
                auto_merged=False, # SAFETY REQUIREMENT
                user_confirmed=None
            )

        # 1. Transliteration Check (e.g. Devanagari to Latin)
        has_devanagari_a = any('\u0900' <= ch <= '\u097F' for ch in name_a)
        has_devanagari_b = any('\u0900' <= ch <= '\u097F' for ch in name_b)
        
        norm_a = cls.transliterate_devanagari(name_a) if has_devanagari_a else name_a
        norm_b = cls.transliterate_devanagari(name_b) if has_devanagari_b else name_b

        if has_devanagari_a or has_devanagari_b:
            explanations.append(EntityMatchExplanation(
                factor="SCRIPT_TRANSLITERATION",
                description="Cross-script phonetic mapping applied between Devanagari and Latin characters.",
                score_impact=30.0
            ))
            confidence += 30.0

        # 2. Honorifics stripping
        cleaned_a, hon_a = cls.strip_honorifics(norm_a)
        cleaned_b, hon_b = cls.strip_honorifics(norm_b)

        if hon_a or hon_b:
            explanations.append(EntityMatchExplanation(
                factor="HONORIFIC_NORMALIZATION",
                description=f"Standardized honorific prefixes: ({hon_a or 'none'}) vs ({hon_b or 'none'}).",
                score_impact=15.0
            ))
            confidence += 15.0

        toks_a = cls.normalize_tokens(cleaned_a)
        toks_b = cls.normalize_tokens(cleaned_b)

        # Direct token equality after normalization
        if toks_a == toks_b:
            confidence += 50.0
            explanations.append(EntityMatchExplanation(
                factor="NORMALIZED_TOKEN_MATCH",
                description="All tokens match identically after phonetic and honorific normalization.",
                score_impact=50.0
            ))
        else:
            # 3. Check initials expansion (e.g. R. K. Sharma vs Rajesh Kumar Sharma)
            is_initials, score_init, detail_init = cls.check_initials_expansion(toks_a, toks_b)
            if is_initials:
                confidence += score_init
                explanations.append(EntityMatchExplanation(
                    factor="INITIALS_EXPANSION",
                    description=detail_init,
                    score_impact=score_init
                ))

            # 4. Check token ordering/inversion (e.g. Sharma Rajesh Kumar)
            is_permuted, score_perm, detail_perm = cls.check_token_permutation(toks_a, toks_b)
            if is_permuted:
                confidence += score_perm
                explanations.append(EntityMatchExplanation(
                    factor="NAME_ORDER_INVERSION",
                    description=detail_perm,
                    score_impact=score_perm
                ))

            # 5. Overlapping token Jaccard similarity
            shared = set(toks_a).intersection(set(toks_b))
            if shared:
                jaccard = len(shared) / max(len(set(toks_a).union(set(toks_b))), 1)
                shared_score = jaccard * 25.0
                confidence += shared_score
                explanations.append(EntityMatchExplanation(
                    factor="SHARED_TOKEN_OVERLAP",
                    description=f"Shared {len(shared)} common surname/family tokens: {', '.join(shared)}",
                    score_impact=shared_score
                ))

        final_confidence = min(round(confidence, 1), 99.0) # Reserve 100 for exact match

        if final_confidence >= 80.0:
            tier = "HIGH_CONFIDENCE_MATCH"
        elif final_confidence >= 60.0:
            tier = "PROBABLE_MATCH"
        elif final_confidence >= 40.0:
            tier = "POSSIBLE_DISCREPANCY"
        else:
            tier = "MISMATCH"

        return EntityMatchResult(
            entity_a_value=name_a,
            entity_b_value=name_b,
            entity_type="PERSON_NAME",
            overall_confidence=final_confidence,
            rank=rank,
            ranked_explanations=explanations,
            match_tier=tier,
            auto_merged=False, # STRICT REQUIREMENT: Never auto-merge records!
            user_confirmed=None
        )
