"""Tests for the per-plugin key-value storage."""
from __future__ import annotations

import json
import time

import pytest

from scruxy.plugin.storage import PluginStorage


class TestPluginStorage:

    def test_get_set(self, tmp_path):
        storage = PluginStorage(str(tmp_path), "test_plugin")
        storage.set("key1", "value1")
        assert storage.get("key1") == "value1"

    def test_get_default(self, tmp_path):
        storage = PluginStorage(str(tmp_path), "test_plugin")
        assert storage.get("missing") is None
        assert storage.get("missing", "default") == "default"

    def test_delete(self, tmp_path):
        storage = PluginStorage(str(tmp_path), "test_plugin")
        storage.set("key1", "value1")
        assert storage.delete("key1") is True
        assert storage.get("key1") is None
        assert storage.delete("key1") is False

    def test_keys(self, tmp_path):
        storage = PluginStorage(str(tmp_path), "test_plugin")
        storage.set("a", 1)
        storage.set("b", 2)
        assert sorted(storage.keys()) == ["a", "b"]

    def test_ttl_expiration(self, tmp_path):
        storage = PluginStorage(str(tmp_path), "test_plugin")
        storage.set("expires", "soon", ttl_seconds=0.01)
        assert storage.get("expires") == "soon"
        time.sleep(0.02)
        assert storage.get("expires") is None

    def test_ttl_not_expired(self, tmp_path):
        storage = PluginStorage(str(tmp_path), "test_plugin")
        storage.set("long", "lived", ttl_seconds=3600)
        assert storage.get("long") == "lived"

    def test_flush_and_reload(self, tmp_path):
        storage1 = PluginStorage(str(tmp_path), "test_plugin")
        storage1.set("persist", "me")
        storage1.flush()

        storage2 = PluginStorage(str(tmp_path), "test_plugin")
        assert storage2.get("persist") == "me"

    def test_namespace_isolation(self, tmp_path):
        s1 = PluginStorage(str(tmp_path), "plugin_a")
        s2 = PluginStorage(str(tmp_path), "plugin_b")
        s1.set("key", "from_a")
        s2.set("key", "from_b")
        s1.flush()
        s2.flush()

        s1_reload = PluginStorage(str(tmp_path), "plugin_a")
        s2_reload = PluginStorage(str(tmp_path), "plugin_b")
        assert s1_reload.get("key") == "from_a"
        assert s2_reload.get("key") == "from_b"

    def test_complex_values(self, tmp_path):
        storage = PluginStorage(str(tmp_path), "test_plugin")
        storage.set("dict", {"nested": [1, 2, 3]})
        storage.flush()
        storage2 = PluginStorage(str(tmp_path), "test_plugin")
        assert storage2.get("dict") == {"nested": [1, 2, 3]}

    def test_expired_entries_evicted_on_flush(self, tmp_path):
        storage = PluginStorage(str(tmp_path), "test_plugin")
        storage.set("expired", "gone", ttl_seconds=0.01)
        storage.set("alive", "here")
        time.sleep(0.02)
        storage.flush()

        raw = json.loads((tmp_path / "test_plugin" / "kv_store.json").read_text())
        assert "expired" not in raw
        assert "alive" in raw

    def test_empty_storage_no_file(self, tmp_path):
        """Storage works without an existing file."""
        storage = PluginStorage(str(tmp_path), "new_plugin")
        assert storage.keys() == []
        assert storage.get("anything") is None
