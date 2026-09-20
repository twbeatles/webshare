"""Google Drive client for WebShare cloud sync."""

from ._base import GoogleDriveBase
from .auth import GoogleDriveAuthMixin
from .files import GoogleDriveFilesMixin
from .http import GoogleDriveHttpMixin
from .sync import GoogleDriveSyncMixin


class GoogleDriveClient(
    GoogleDriveAuthMixin,
    GoogleDriveHttpMixin,
    GoogleDriveFilesMixin,
    GoogleDriveSyncMixin,
    GoogleDriveBase,
):
    """Composed client; behavior unchanged (see responsibility mixins)."""
