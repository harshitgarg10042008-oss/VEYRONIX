"""Confidence-aware deterministic vendor detection."""
from __future__ import annotations

from dataclasses import dataclass

from .parsers import PARSER_REGISTRY, VendorParser


@dataclass(frozen=True)
class VendorCandidate:
    vendor: str
    confidence: float
    parser_version: str


@dataclass(frozen=True)
class VendorDetection:
    selected_vendor: str | None
    confidence: float
    ambiguous: bool
    reason: str
    candidates: tuple[VendorCandidate, ...]


def detect_vendor(text: str, *, minimum_confidence: float = 0.5, minimum_margin: float = 0.15) -> VendorDetection:
    if not isinstance(text, str) or not text.strip():
        return VendorDetection(None, 0.0, False, "configuration is empty", ())
    candidates = tuple(sorted((_candidate(parser, text) for parser in PARSER_REGISTRY), key=lambda item: item.confidence, reverse=True))
    top = candidates[0]
    second = candidates[1] if len(candidates) > 1 else None
    if top.confidence < minimum_confidence:
        return VendorDetection(None, top.confidence, False, "no parser reached the confidence threshold", candidates)
    if second and top.confidence - second.confidence < minimum_margin:
        return VendorDetection(None, top.confidence, True, "top parser candidates are too close to select safely", candidates)
    return VendorDetection(top.vendor, top.confidence, False, "selected by deterministic parser signals", candidates)


def _candidate(parser: VendorParser, text: str) -> VendorCandidate:
    return VendorCandidate(parser.plugin_id, round(max(0.0, min(1.0, parser.detect(text))), 3), parser.parser_version)
