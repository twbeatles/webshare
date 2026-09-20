"""Composed GuiActionsMixin."""

from __future__ import annotations
# pyright: reportAttributeAccessIssue=false, reportArgumentType=false
from .server_actions import ServerActionsMixin
from .log_actions import LogActionsMixin
from .update_actions import UpdateActionsMixin


class GuiActionsMixin(ServerActionsMixin, LogActionsMixin, UpdateActionsMixin):
    """Composed GUI actions (behavior unchanged; see responsibility mixins)."""
