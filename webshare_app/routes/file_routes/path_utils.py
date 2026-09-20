"""Path helpers for copy/move conflict handling."""

import os
from config import conf
from utils.request_policy import is_protected_system_path
from utils.helpers import create_file_version




def _normcase_path(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))




def _is_descendant_path(parent: str, child: str) -> bool:
    parent_key = _normcase_path(parent)
    child_key = _normcase_path(child)
    if parent_key == child_key:
        return False
    try:
        return os.path.commonpath([parent_key, child_key]) == parent_key
    except ValueError:
        return False




def _create_overwrite_versions_if_needed(path: str):
    if os.path.isfile(path) and not os.path.islink(path):
        create_file_version(path)
        return
    if not os.path.isdir(path) or os.path.islink(path):
        return

    base_dir = conf.get('folder')
    for root, dirnames, filenames in os.walk(path):
        dirnames[:] = [
            dirname for dirname in dirnames
            if not is_protected_system_path(os.path.relpath(os.path.join(root, dirname), base_dir).replace('\\', '/'))
        ]
        for filename in filenames:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, base_dir).replace('\\', '/')
            if is_protected_system_path(rel_path) or os.path.islink(file_path):
                continue
            create_file_version(file_path)

