"""
Google Drive sync client.

Split package (SRP): auth/token handling, HTTP primitives, remote file
operations, and sync orchestration each live in their own mixin module.
`GoogleDriveClient` composes them with behavior unchanged.
"""

from .client import GoogleDriveClient

__all__ = ["GoogleDriveClient"]
