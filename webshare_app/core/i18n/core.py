"""i18n lookup logic (language registry + translation accessors)."""

from .translations_en import EN
from .translations_ko import KO


I18N = {
    'ko': KO,
    'en': EN,
}


# 누락 키 경고 (개발 모드용)
_warned_keys = set()


def get_text(key: str, lang: str | None = None) -> str:
    """다국어 텍스트 반환"""
    from config import conf
    if lang is None:
        lang = conf.get('language', 'ko')

    translations = I18N.get(lang, I18N['ko'])
    if key in translations:
        return translations[key]

    # 누락 키 경고 (한 번만)
    if key not in _warned_keys:
        _warned_keys.add(key)
        # 로거 순환 import 방지를 위해 print 사용
        print(f"[WARN] i18n: 누락된 번역 키 '{key}' (lang={lang})")

    return key


def get_all_translations(lang: str | None = None) -> dict[str, str]:
    """모든 번역을 딕셔너리로 반환 (템플릿/JavaScript용)"""
    from config import conf
    if lang is None:
        lang = conf.get('language', 'ko')

    return I18N.get(lang, I18N['ko']).copy()


def get_current_language() -> str:
    """현재 언어 코드 반환"""
    from config import conf
    return conf.get('language', 'ko')
