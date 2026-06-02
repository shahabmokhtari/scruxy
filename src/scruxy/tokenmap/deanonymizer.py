"""Reverse token replacements (unscrub) with trie-based SSE chunk buffering."""
from __future__ import annotations

from scruxy.tokenmap.token_map import TokenMap


# ---------------------------------------------------------------------------
# Deanonymizer — full-text token replacement
# ---------------------------------------------------------------------------


class Deanonymizer:
    """Replace tokens in text with original PII values.

    Supports any token format (``REDACTED_*``, UUIDs, script-generated, etc.)
    by iterating over the unscrub map with longest-first replacement.
    """

    @staticmethod
    def deanonymize_text(text: str, token_map: TokenMap) -> str:
        """Replace all known tokens in *text* with their original PII.

        Uses a single-pass regex approach to avoid cascading replacements
        where one token's PII value contains text matching another token.

        Args:
            text: Scrubbed text potentially containing redaction tokens.
            token_map: The session's :class:`TokenMap`.

        Returns:
            Text with tokens replaced by original PII values.
        """
        import re as _re_mod
        unscrub = token_map.unscrub_map
        if not unscrub:
            return text
        sorted_tokens = sorted(unscrub.keys(), key=len, reverse=True)
        pattern = _re_mod.compile("|".join(_re_mod.escape(t) for t in sorted_tokens))
        return pattern.sub(lambda m: unscrub[m.group(0)], text)


# ---------------------------------------------------------------------------
# Trie node for prefix matching
# ---------------------------------------------------------------------------

class _TrieNode:
    """Internal trie node for efficient prefix matching of token strings."""

    __slots__ = ("children", "value")

    def __init__(self) -> None:
        self.children: dict[str, _TrieNode] = {}
        self.value: str | None = None  # replacement PII when this is a terminal node


class _Trie:
    """Prefix trie built from all current unscrub tokens."""

    def __init__(self) -> None:
        self.root = _TrieNode()

    def insert(self, key: str, value: str) -> None:
        """Insert *key* (token) mapping to *value* (original PII)."""
        node = self.root
        for ch in key:
            if ch not in node.children:
                node.children[ch] = _TrieNode()
            node = node.children[ch]
        node.value = value

    def search_prefix(self, text: str, start: int = 0) -> tuple[str | None, int]:
        """Find the longest token match starting at *text[start:]*.

        Returns:
            ``(replacement_value, match_length)`` if a complete token is found,
            otherwise ``(None, 0)``.
        """
        node = self.root
        best_value: str | None = None
        best_length = 0
        length = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch not in node.children:
                break
            node = node.children[ch]
            length += 1
            if node.value is not None:
                best_value = node.value
                best_length = length
        return best_value, best_length

    def has_prefix(self, text: str) -> bool:
        """Return ``True`` if *text* is a prefix of any key in the trie."""
        node = self.root
        for ch in text:
            if ch not in node.children:
                return False
            node = node.children[ch]
        return True

    def has_longer_match(self, text: str) -> bool:
        """Return ``True`` if *text* is a complete token AND the trie has a strictly longer token starting with *text*."""
        node = self.root
        for ch in text:
            if ch not in node.children:
                return False
            node = node.children[ch]
        # text must be a complete token and have children (= longer tokens exist)
        return node.value is not None and bool(node.children)


def _build_trie(token_map: TokenMap) -> _Trie:
    """Build a trie from the token map's unscrub dictionary."""
    trie = _Trie()
    for token, pii in token_map.unscrub_map.items():
        trie.insert(token, pii)
    return trie


# ---------------------------------------------------------------------------
# SSEChunkBuffer — rolling buffer for SSE streaming deanonymization
# ---------------------------------------------------------------------------

class SSEChunkBuffer:
    """Rolling buffer that handles token splits across SSE chunk boundaries.

    When streaming SSE responses, a redaction token may be split across
    two consecutive chunks.  This buffer holds back up to
    *max_token_length* trailing characters that could be the start of a
    partial token, emitting only text that is safe (i.e. cannot be part of
    a future token).

    Supports any token format (``REDACTED_*``, UUIDs, script-generated, etc.)
    by consulting the trie built from the actual token map.

    Usage::

        buf = SSEChunkBuffer(token_map)
        for chunk in sse_stream:
            safe = buf.feed(chunk)
            yield safe
        yield buf.flush()  # emit any remaining buffered text
    """

    def __init__(self, token_map: TokenMap, max_token_length: int = 40) -> None:
        self._token_map = token_map
        # R67-4 fix: derive the actual max token length from the
        # token map at construction time and on every trie rebuild,
        # rather than hardcoding 40.  Custom replacement strategies
        # (script output, UUID, hashed names) can produce tokens
        # well over 40 chars; the prior cap caused those tokens to
        # be emitted raw when split across SSE chunk boundaries.
        # Argument is kept as a floor (lower bound) for back-compat.
        self._max_token_length = max(
            max_token_length, self._compute_max_token_length(token_map)
        )
        self._buffer: str = ""
        self._trie: _Trie = _build_trie(token_map)

    @staticmethod
    def _compute_max_token_length(token_map: TokenMap) -> int:
        """Compute the longest token literal in the token map."""
        try:
            unscrub = getattr(token_map, "unscrub_map", {}) or {}
            if not unscrub:
                return 0
            return max(len(t) for t in unscrub)
        except Exception:
            return 0

    def rebuild_trie(self) -> None:
        """Rebuild the internal trie (call if the token map has changed)."""
        self._trie = _build_trie(self._token_map)
        # R67-4 fix: also refresh max_token_length so newly-added
        # long tokens are accounted for in the partial-prefix cap.
        new_max = self._compute_max_token_length(self._token_map)
        if new_max > self._max_token_length:
            self._max_token_length = new_max

    def feed(self, chunk: str) -> str:
        """Feed a new *chunk* and return text safe to emit.

        Characters that might be the start of a partial token are held in the
        internal buffer and will be emitted once the ambiguity is resolved or
        on :meth:`flush`.
        """
        self._buffer += chunk
        return self._drain()

    def flush(self) -> str:
        """Emit all buffered text, replacing any complete tokens found.

        Partial matches that never completed are emitted as-is.
        """
        result = Deanonymizer.deanonymize_text(self._buffer, self._token_map)
        self._buffer = ""
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _drain(self) -> str:
        """Process the buffer: replace complete tokens, hold back partial prefixes."""
        output_parts: list[str] = []
        buf = self._buffer
        trie_starts = self._trie.root.children  # first chars of all tokens
        i = 0

        while i < len(buf):
            # Check if this position could be the start of any token.
            if buf[i] in trie_starts:
                # Try to match a full token from the trie.
                replacement, length = self._trie.search_prefix(buf, i)
                if replacement is not None:
                    # Complete match -- emit the replacement.
                    output_parts.append(replacement)
                    i += length
                    continue

                # Check if remaining text could be a prefix of a token.
                remaining = buf[i:]
                if len(remaining) < self._max_token_length and self._trie.has_prefix(remaining):
                    # Potential partial match -- hold in buffer.
                    self._buffer = remaining
                    return "".join(output_parts)

                # Not a valid prefix; emit the character and move on.
                output_parts.append(buf[i])
                i += 1
            else:
                # Fast scan: advance to the next potential token start.
                next_start = -1
                for j in range(i + 1, len(buf)):
                    if buf[j] in trie_starts:
                        next_start = j
                        break
                if next_start == -1:
                    output_parts.append(buf[i:])
                    i = len(buf)
                else:
                    output_parts.append(buf[i:next_start])
                    i = next_start

        self._buffer = ""
        return "".join(output_parts)
