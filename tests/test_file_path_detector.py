"""Tests for the file_path detector plugin."""
import sys
import os

import pytest

# Support importing both the builtin and example_plugins version
try:
    from scruxy.plugin.file_path import FilePathDetector
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "example_plugins"))
    from file_path_detector import FilePathDetector


@pytest.fixture
def detector():
    d = FilePathDetector()
    d.setup({"score": 0.95})
    return d


class TestWindowsPaths:
    def test_simple_backslash_path(self, detector):
        text = r"Look at C:\importantproject\secure\file.txt for details"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["importantproject", "secure", "file"]

    def test_double_backslash_path(self, detector):
        text = "Found in C:\\\\Users\\\\admin\\\\doc.pdf"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["Users", "admin", "doc"]

    def test_forward_slash_windows(self, detector):
        text = "File at D:/projects/myapp/main.py is key"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["projects", "myapp", "main"]

    def test_directory_only(self, detector):
        text = "Check C:\\Users\\john\\Documents\\"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["Users", "john", "Documents"]

    def test_root_only(self, detector):
        text = r"Drive C:\ is full"
        entities = detector.detect(text)
        assert entities == []


class TestLinuxPaths:
    def test_home_path(self, detector):
        text = "Config at /home/alice/.config/app.yaml"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["alice", ".config", "app"]

    def test_src_path(self, detector):
        text = "Source in /src/components/Button.tsx"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["components", "Button"]

    def test_usr_path(self, detector):
        text = "Binary at /usr/local/bin/mytools"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["local", "bin", "mytools"]

    def test_etc_path(self, detector):
        text = "Edit /etc/nginx/nginx.conf"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["nginx", "nginx"]

    def test_directory_no_file(self, detector):
        text = "Look in /var/log/app/"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["log", "app"]


class TestMacPaths:
    def test_users_path(self, detector):
        text = "Open /Users/alice/work/app/config.json"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["alice", "work", "app", "config"]

    def test_library_path(self, detector):
        text = "Check /Library/MyApp/config.yaml"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert "MyApp" in segments
        assert "config" in segments


class TestMinSegments:
    def test_two_segment_path_skipped(self, detector):
        """Paths with only root + 1 segment (2 total) are too short to scrub."""
        text = r"C:\Users is a folder"
        entities = detector.detect(text)
        assert entities == []

    def test_two_segment_linux_skipped(self, detector):
        text = "See /home/alice for details"
        entities = detector.detect(text)
        assert entities == []

    def test_three_segment_path_matched(self, detector):
        text = r"C:\Users\admin is a folder"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["Users", "admin"]

    def test_custom_min_segments(self):
        d = FilePathDetector()
        d.setup({"score": 0.95, "min_segments": 4})
        text = r"C:\Users\admin\docs\file.txt"
        entities = d.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["Users", "admin", "docs", "file"]
        # 3-segment path should be skipped with min_segments=4
        text2 = r"C:\Users\admin"
        assert d.detect(text2) == []


class TestTrailingDots:
    def test_trailing_dot_not_matched(self, detector):
        """Words ending with a dot (like 'Claude.') must not be treated as paths."""
        text = "You are Claude Code, Anthropic's official CLI for Claude."
        entities = detector.detect(text)
        assert entities == []

    def test_sentence_ending_dot(self, detector):
        text = "Check the file at C:\\projects\\secret\\data.csv."
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["projects", "secret", "data"]

    def test_dotfile_in_path(self, detector):
        """Dotfiles like .config should still be matched within a valid path."""
        text = "Edit /home/user/.config/app.yaml"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["user", ".config", "app"]


class TestEdgeCases:
    def test_no_paths(self, detector):
        text = "This is just regular text with no paths."
        entities = detector.detect(text)
        assert entities == []

    def test_relative_path_not_matched(self, detector):
        text = "See tree/apple for the result"
        entities = detector.detect(text)
        assert entities == []

    def test_multiple_paths(self, detector):
        text = r"Copy C:\src\old\a.txt to D:\dst\new\b.txt"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["src", "old", "a", "dst", "new", "b"]

    def test_empty_text(self, detector):
        entities = detector.detect("")
        assert entities == []

    def test_entity_type_and_source(self, detector):
        text = r"C:\foo\bar\baz.txt"
        entities = detector.detect(text)
        for e in entities:
            assert e.entity_type == "PATH_SEGMENT"
            assert e.source == "file_path"
            assert e.score == 0.95

    def test_file_extension_preserved(self, detector):
        """Ensure the dot+extension is NOT part of the entity."""
        text = r"C:\data\reports\report.xlsx"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert "report" in segments
        assert "report.xlsx" not in segments


class TestUrlExclusion:
    """URLs should never be detected as file paths."""

    def test_https_url_with_path(self, detector):
        text = "Visit https://example.com/src/components/Button.tsx for docs"
        entities = detector.detect(text)
        assert entities == []

    def test_http_url_with_path(self, detector):
        text = "See http://docs.example.com/usr/local/share/data"
        entities = detector.detect(text)
        assert entities == []

    def test_ftp_url_with_path(self, detector):
        text = "Download from ftp://server.org/home/user/files/data.csv"
        entities = detector.detect(text)
        assert entities == []

    def test_bare_domain_with_path(self, detector):
        text = "Check api.github.com/src/components/file.js for the API"
        entities = detector.detect(text)
        assert entities == []

    def test_bare_domain_xyz_com(self, detector):
        text = "See xyz.com/home/alice/docs/readme.md for details"
        entities = detector.detect(text)
        assert entities == []

    def test_url_does_not_affect_real_path(self, detector):
        """A real path in the same text should still be detected."""
        text = "See https://example.com/src/stuff and also C:\\Users\\admin\\secret\\file.txt"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert "Users" in segments
        assert "admin" in segments
        assert "secret" in segments
        assert "file" in segments

    def test_https_with_port(self, detector):
        text = "API at https://localhost:3000/src/api/handlers/auth.js"
        entities = detector.detect(text)
        assert entities == []

    def test_git_ssh_url(self, detector):
        text = "Clone git://github.com/src/repo/lib/utils.js"
        entities = detector.detect(text)
        assert entities == []

    def test_file_scheme_url(self, detector):
        text = "Open file:///home/user/docs/report.pdf in browser"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert segments == ["user", "docs", "report"]

    def test_web_config_path_still_detected(self, detector):
        text = "Inspect /home/alice/web.config/app/settings.json now"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert "web.config" in segments

    def test_file_scheme_does_not_block_real_windows_path(self, detector):
        text = "See file://server/share and also C:\\Users\\bob\\docs\\file.txt"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert "Users" in segments
        assert "bob" in segments

    def test_real_path_still_works(self, detector):
        """Ensure normal file paths are still detected correctly."""
        text = "Config at /home/alice/.config/app.yaml and C:\\Users\\bob\\docs\\file.txt"
        entities = detector.detect(text)
        segments = [text[e.start:e.end] for e in entities]
        assert "alice" in segments
        assert ".config" in segments
        assert "Users" in segments
        assert "bob" in segments
