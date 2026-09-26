from __future__ import annotations

import argparse
import bisect
import re
from pathlib import Path

RAW_STRING_START = re.compile(r'(?:u8|u|U|L)?R"([^ ()\\\t\r\n]{0,16})\(')
STRING_START = re.compile(r'(?:u8|u|U|L)?["\']')
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hh", ".hpp"}

def _line_starts(source: str) -> list[int]:
    starts = [0]
    starts.extend(match.end() for match in re.finditer("\n", source))
    return starts

def _skip_preprocessor_line(source: str, index: int) -> int:
    line_start = source.rfind("\n", 0, index) + 1
    if source[line_start:index].strip():
        return index

    while True:
        line_end = source.find("\n", index)
        if line_end == -1:
            return len(source)
        line = source[index:line_end].rstrip("\r")
        index = line_end + 1
        if not line.rstrip().endswith("\\"):
            return index

def _tokens(source: str) -> list[tuple[str, int]]:
    starts = _line_starts(source)
    result: list[tuple[str, int]] = []
    index = 0
    length = len(source)

    def add(value: str, offset: int) -> None:
        result.append((value, bisect.bisect_right(starts, offset) - 1))

    while index < length:
        char = source[index]

        if char.isspace():
            index += 1
            continue

        if char == "#":
            skipped = _skip_preprocessor_line(source, index)
            if skipped != index:
                index = skipped
                continue

        if source.startswith("//", index):
            newline = source.find("\n", index)
            index = length if newline == -1 else newline + 1
            continue

        if source.startswith("/*", index):
            comment_end = source.find("*/", index + 2)
            index = length if comment_end == -1 else comment_end + 2
            continue

        raw_match = RAW_STRING_START.match(source, index)
        if raw_match:
            terminator = ")" + raw_match.group(1) + '"'
            literal_end = source.find(terminator, raw_match.end())
            index = length if literal_end == -1 else literal_end + len(terminator)
            continue

        string_match = STRING_START.match(source, index)
        if string_match:
            quote = string_match.group(0)[-1]
            index += len(string_match.group(0))
            while index < length:
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            continue

        identifier = IDENTIFIER.match(source, index)
        if identifier:
            add(identifier.group(0), index)
            index = identifier.end()
            continue

        add(char, index)
        index += 1

    return result

def _delimiter_pairs(tokens: list[tuple[str, int]], opening: str, closing: str) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for index, (value, _) in enumerate(tokens):
        if value == opening:
            stack.append(index)
        elif value == closing and stack:
            pairs[stack.pop()] = index
    return pairs

def _skip_attributes(tokens: list[tuple[str, int]], index: int) -> int:
    while (
        index + 1 < len(tokens)
        and tokens[index][0] == "["
        and tokens[index + 1][0] == "["
    ):
        index += 2
        while index + 1 < len(tokens):
            if tokens[index][0] == "]" and tokens[index + 1][0] == "]":
                index += 2
                break
            index += 1
    return index

def _body_open(
    index: int,
    tokens: list[tuple[str, int]],
    parens: dict[int, int],
    *,
    allow_if_modifier: bool = False,
) -> int | None:
    cursor = index + 1
    if allow_if_modifier and cursor < len(tokens) and tokens[cursor][0] in {
        "constexpr",
        "consteval",
    }:
        cursor += 1
    if cursor >= len(tokens) or tokens[cursor][0] != "(":
        return None
    close_paren = parens.get(cursor)
    if close_paren is None:
        return None
    cursor = _skip_attributes(tokens, close_paren + 1)
    if cursor < len(tokens) and tokens[cursor][0] == "{":
        return cursor
    return None

def _simple_statement_end(tokens: list[tuple[str, int]], index: int) -> int:
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    for cursor in range(index, len(tokens)):
        value = tokens[cursor][0]
        if value == ";" and paren_depth == bracket_depth == brace_depth == 0:
            return cursor
        if value == "(":
            paren_depth += 1
        elif value == ")":
            paren_depth = max(0, paren_depth - 1)
        elif value == "[":
            bracket_depth += 1
        elif value == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif value == "{":
            brace_depth += 1
        elif value == "}":
            if brace_depth == 0:
                return max(index, cursor - 1)
            brace_depth -= 1
    return len(tokens) - 1

def _control_spans(tokens: list[tuple[str, int]]) -> list[tuple[int, int]]:
    braces = _delimiter_pairs(tokens, "{", "}")
    parens = _delimiter_pairs(tokens, "(", ")")

    def parse_if(index: int) -> int | None:
        body = _body_open(index, tokens, parens, allow_if_modifier=True)
        if body is None or body not in braces:
            return None
        end = braces[body]
        branch = end + 1
        if branch >= len(tokens) or tokens[branch][0] != "else":
            return end

        alternative = branch + 1
        if alternative >= len(tokens):
            return end
        if tokens[alternative][0] == "if":
            return parse_if(alternative) or _simple_statement_end(tokens, alternative)
        if tokens[alternative][0] == "{":
            return braces.get(alternative, end)
        return _simple_statement_end(tokens, alternative)

    spans: list[tuple[int, int]] = []
    for index, (keyword, _) in enumerate(tokens):
        if keyword == "if":
            if index > 0 and tokens[index - 1][0] == "else":
                continue
            end = parse_if(index)
            if end is not None:
                spans.append((index, end))
        elif keyword in {"for", "while", "switch"}:
            body = _body_open(index, tokens, parens)
            if body is not None and body in braces:
                spans.append((index, braces[body]))
        elif keyword == "do":
            body = index + 1
            if body not in braces or tokens[body][0] != "{":
                continue
            end = braces[body]
            trailer = end + 1
            if trailer + 1 < len(tokens) and tokens[trailer][0] == "while":
                open_paren = trailer + 1
                close_paren = parens.get(open_paren)
                if close_paren is not None:
                    end = close_paren + 1
                    if end < len(tokens) and tokens[end][0] == ";":
                        pass
            spans.append((index, end))
        elif keyword == "try":
            body = index + 1
            if body not in braces or tokens[body][0] != "{":
                continue
            end = braces[body]
            while end + 1 < len(tokens) and tokens[end + 1][0] == "catch":
                cursor = end + 2
                if cursor < len(tokens) and tokens[cursor][0] == "(":
                    cursor = parens.get(cursor, cursor) + 1
                if cursor >= len(tokens) or tokens[cursor][0] != "{":
                    break
                catch_end = braces.get(cursor)
                if catch_end is None:
                    break
                end = catch_end
            spans.append((index, end))

    return spans

def _comment_line(line: str) -> bool:
    stripped = line.strip()
    return (
        stripped.startswith("//")
        or stripped.startswith("/*")
        or stripped.startswith("*")
        or stripped.endswith("*/")
    )

def _spacing_positions(lines: list[str], spans: list[tuple[int, int]]) -> set[int]:
    positions: set[int] = set()
    for start_token, end_token in spans:
        start_line = start_token
        end_line = end_token

        if start_line > len(lines) - 1 or end_line > len(lines) - 1:
            continue

        comment_start = start_line
        while comment_start > 0 and _comment_line(lines[comment_start - 1]):
            comment_start -= 1

        if comment_start > 0 and lines[comment_start - 1].strip():
            previous = lines[comment_start - 1].strip()
            if not previous.endswith(("{", ":")):
                positions.add(comment_start)

        if end_line + 1 < len(lines) and lines[end_line + 1].strip():
            following = lines[end_line + 1].lstrip()
            if not following.startswith("}") and not re.match(
                r"(?:else|catch)\b", following
            ):
                positions.add(end_line + 1)

    return positions

def _format_file(path: Path) -> bool:
    source = path.read_text(encoding="utf-8")
    tokens = _tokens(source)
    if not tokens:
        return False

    lines = source.splitlines()
    spans = _control_spans(tokens)
    if not spans:
        return False

    line_spans = [(tokens[start][1], tokens[end][1]) for start, end in spans]
    positions = _spacing_positions(lines, line_spans)
    if not positions:
        return False

    output: list[str] = []
    for index, line in enumerate(lines):
        if index in positions and output and output[-1].strip():
            output.append("")
        output.append(line)

    newline = "\r\n" if "\r\n" in source else "\n"
    result = newline.join(output)
    if source.endswith(("\n", "\r")):
        result += newline
    if result == source:
        return False

    path.write_text(result, encoding="utf-8", newline="")
    return True

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    root = parser.parse_args().root

    changed = 0
    for directory in (root / "src", root / "tests"):
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
                changed += _format_file(path)

    print(f"Spaced stuff in {changed} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
