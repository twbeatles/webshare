"""Public-surface guarantees for the SOLID split refactor.

Former mega-modules are now packages. This test locks the import surface
 so a later change cannot silently drop a public name, seam, or handler.
"""

import os

from webshare_app.services.google_drive_client import GoogleDriveClient


def test_helpers_surface_and_submodule_identity():
    import webshare_app.utils.helpers as helpers
    from webshare_app.utils.helpers import download_quota, file_versions

    expected = {
        "add_recent_file",
        "atomic_copy_file",
        "atomic_save_upload",
        "atomic_write_bytes",
        "build_download_tracker_key",
        "build_recent_owner_key",
        "build_version_filename",
        "check_download_limit",
        "cleanup_expired_download_trackers",
        "cleanup_expired_sessions",
        "cleanup_expired_share_links",
        "cleanup_old_versions",
        "cleanup_upload_temp_dirs",
        "create_file_version",
        "get_recent_files",
        "reserve_download_quota",
        "rollback_download_quota",
        "track_download",
        "version_name_matches_rel_path",
    }
    assert expected <= set(helpers.__all__)
    for name in expected:
        assert callable(getattr(helpers, name)), name
    # Re-exports are the same function objects (no copies).
    assert helpers.check_download_limit is download_quota.check_download_limit
    assert helpers.create_file_version is file_versions.create_file_version


def test_quota_monkeypatch_contract_preserved(monkeypatch):
    import utils.helpers as helpers

    monkeypatch.setattr(
        "utils.helpers.check_download_limit",
        lambda _key, _count=True, projected_bytes=0: (False, "limit exceeded"),
    )
    allowed, message, reservation = helpers.reserve_download_quota("ip:1.2.3.4", True)
    assert allowed is False
    assert message == "limit exceeded"
    assert reservation == {}


def test_i18n_split_preserves_translations():
    from webshare_app.core import i18n
    from webshare_app.core.i18n import translations_en, translations_ko

    assert set(i18n.I18N) == {"ko", "en"}
    assert set(i18n.I18N["ko"]) == set(i18n.I18N["en"])
    assert len(i18n.I18N["ko"]) > 200
    assert i18n.I18N["ko"] is translations_ko.KO
    assert i18n.I18N["en"] is translations_en.EN
    assert isinstance(i18n.get_text("login"), str)
    assert isinstance(i18n.get_all_translations("en"), dict)
    assert i18n.get_current_language() in {"ko", "en"}


def test_file_routes_surface_and_seams():
    from webshare_app.routes import file_routes

    assert file_routes.file_bp.name == "file"
    for handler in (
        "download", "upload", "mkdir", "delete", "rename",
        "copy_item", "move_item", "search_files", "download_zip",
        "unzip_file", "batch_download", "batch_delete",
        "get_file_info", "clipboard_handler", "zip_preview",
    ):
        assert callable(getattr(file_routes, handler)), handler
    assert file_routes.MAX_CLIPBOARD_ENTRIES == 200
    assert file_routes.MAX_CLIPBOARD_CONTENT_BYTES == 256 * 1024
    # Test seams used by monkeypatch MUST resolve on the package.
    assert callable(file_routes.create_temp_zip_from_items)
    assert hasattr(file_routes.indexer, "search")


def test_upload_media_admin_surfaces_and_seams():
    from webshare_app.routes import admin_routes, media_routes, upload_routes

    assert upload_routes.upload_bp.name == "upload"
    assert media_routes.media_bp.name == "media"
    assert admin_routes.admin_bp.name == "admin"
    for module, names in (
        (upload_routes, ("init_chunk_upload", "upload_chunk", "complete_chunk_upload",
                          "cancel_chunk_upload", "cleanup_expired_upload_sessions")),
        (media_routes, ("stream_media", "get_thumbnail", "video_thumbnail", "get_playlist",
                         "get_gallery", "document_preview", "get_content", "save_content",
                         "stream_hls_playlist", "stream_hls_segment")),
        (admin_routes, ("get_users_file_path", "load_users", "save_users",
                         "manage_users", "manage_permissions", "trash_settings",
                         "get_audit_log", "access_dashboard", "system_stats")),
    ):
        for name in names:
            assert callable(getattr(module, name)), f"{module.__name__}.{name}"
    assert isinstance(upload_routes.UPLOAD_SESSIONS, dict)
    assert hasattr(upload_routes.indexer, "update_event")
    assert isinstance(media_routes.MAX_TEXT_EDIT_SIZE, int)
    assert callable(media_routes.atomic_write_bytes)
    assert callable(admin_routes.save_users)
    assert admin_routes.os is os


def test_google_drive_client_composition():
    from webshare_app.services.google_drive_client import (
        auth,
        client,
        files,
        http,
        sync,
    )

    assert issubclass(client.GoogleDriveClient, auth.GoogleDriveAuthMixin)
    assert issubclass(client.GoogleDriveClient, http.GoogleDriveHttpMixin)
    assert issubclass(client.GoogleDriveClient, files.GoogleDriveFilesMixin)
    assert issubclass(client.GoogleDriveClient, sync.GoogleDriveSyncMixin)
    expected_methods = {
        "__init__", "is_connected", "build_auth_url", "exchange_code",
        "disconnect", "sync_upload", "sync_download", "list_children",
        "ensure_folder", "find_child", "upload_file", "download_file",
        "_token", "_ensure_access_token", "_refresh_access_token",
        "_request_json", "_request_bytes", "_request_response",
        "_stream_upload_file", "_stream_download_to_file",
    }
    assert expected_methods <= set(dir(GoogleDriveClient))
    assert GoogleDriveClient(conflict_policy="dry_run").conflict_policy == "dry_run"


def test_search_indexer_singleton_preserved():
    from webshare_app.features import search_indexer
    from webshare_app.features.search_indexer import scanning

    assert isinstance(search_indexer.indexer, search_indexer.SearchIndexer)
    # Same-function reference kept working after the split.
    assert (
        search_indexer.SearchIndexer._normalize_item
        is scanning.ScanningMixin._normalize_item
    )


def test_config_registry_surface():
    from webshare_app.core import config
    from webshare_app.core.config import defaults, manager, schema, state

    assert config.conf is manager.conf
    assert isinstance(config.conf, manager.ConfigManager)
    assert config.ConfigData is schema.ConfigData
    assert config.DEFAULT_PORT == defaults.DEFAULT_PORT
    assert config.STATS is state.STATS
    assert config.CLOUD_SYNC_CONFIG is state.CLOUD_SYNC_CONFIG
    assert isinstance(config.APP_VERSION, str)
    assert config.os is os


def test_gui_mixin_surfaces():
    from webshare_app.gui.actions import GuiActionsMixin
    from webshare_app.gui.tabs import TabBuilderMixin

    for name in ("toggle_server", "update_stats", "save_settings", "check_for_updates"):
        assert callable(getattr(GuiActionsMixin, name)), name
    for name in ("init_ui", "build_home_tab", "build_settings_tab", "build_logs_tab"):
        assert callable(getattr(TabBuilderMixin, name)), name
