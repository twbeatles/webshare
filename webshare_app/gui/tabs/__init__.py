"""
WebShare Pro - GUI Tabs.

Split package (SRP): each tab (home, settings, logs) is built by its own
mixin module. `TabBuilderMixin` composes them with behavior unchanged.
"""

from .mixin import TabBuilderMixin

__all__ = ["TabBuilderMixin"]
