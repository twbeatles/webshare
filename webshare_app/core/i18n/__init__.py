"""
WebShare Pro - Internationalization (i18n).
Split package: per-language data lives in translations_*, lookup logic
in core. The original module surface is re-exported unchanged.
"""

from .core import I18N, _warned_keys, get_all_translations, get_current_language, get_text

__all__ = ["I18N", "get_all_translations", "get_current_language", "get_text"]
