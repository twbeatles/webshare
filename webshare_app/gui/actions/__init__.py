"""
WebShare Pro - GUI Actions.

Split package (SRP): server control, log/statistics, and auto-update
actions each live in their own mixin module. `GuiActionsMixin` composes
them with behavior unchanged.
"""

from .mixin import GuiActionsMixin

__all__ = ["GuiActionsMixin"]
