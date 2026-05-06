"""
Payload Management Module
"""

from typing import List, Dict, Optional, Iterator
from ..payloads.repository import PAYLOADS, PAYLOAD_CATEGORIES


class PayloadManager:
    def __init__(self):
        self.payloads = PAYLOADS
        self.categories = PAYLOAD_CATEGORIES
        self.current_category_index = 0
        self.current_payload_index = 0
        self._flattened_payloads = self._flatten_payloads()

    def _flatten_payloads(self) -> List[Dict]:
        flattened = []
        for category, payload_list in self.payloads.items():
            for payload in payload_list:
                flattened.append({
                    "payload": payload,
                    "category": category,
                    "description": self.categories.get(category, "")
                })
        return flattened

    def get_all_payloads(self) -> List[Dict]:
        return self._flattened_payloads

    def get_payloads_by_category(self, category: str) -> List[str]:
        return self.payloads.get(category, [])

    def get_all_categories(self) -> List[str]:
        return list(self.categories.keys())

    def get_payload_iterator(self) -> Iterator[Dict]:
        return iter(self._flattened_payloads)

    def get_payload_count(self) -> int:
        return len(self._flattened_payloads)

    def get_payload_by_index(self, index: int) -> Optional[Dict]:
        if 0 <= index < len(self._flattened_payloads):
            return self._flattened_payloads[index]
        return None

    def filter_payloads(
        self,
        categories: Optional[List[str]] = None,
        min_effectiveness: float = 0.0
    ) -> List[Dict]:
        filtered = self._flattened_payloads
        if categories:
            filtered = [p for p in filtered if p["category"] in categories]
        return filtered

    def get_payloads_for_context(self, context: str) -> List[str]:
        context_map = {
            "html": ["basic", "script_tags", "svg_based", "iframe_based", "polyglot"],
            "attribute": ["event_handlers", "basic", "polyglot"],
            "javascript": ["dom_based", "script_tags", "mutation_xss"],
            "url": ["data_urls", "javascript", "dom_based"],
            "style": ["basic", "comment_obfuscation"],
        }
        relevant_categories = context_map.get(context.lower(), ["basic"])
        result = []
        for category in relevant_categories:
            if category in self.payloads:
                result.extend(self.payloads[category])
        return result

    def get_basic_payloads(self) -> List[str]:
        return self.payloads.get("basic", [])

    def get_bypass_payloads(self) -> List[Dict]:
        bypass_categories = [
            "encoding_bypass",
            "case_mixing",
            "comment_obfuscation",
            "null_byte"
        ]
        result = []
        for category in bypass_categories:
            if category in self.payloads:
                for payload in self.payloads[category]:
                    result.append({
                        "payload": payload,
                        "category": category
                    })
        return result
