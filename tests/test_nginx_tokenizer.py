import pytest

from webconf_audit.local.nginx.parser.parser import NginxParseError, NginxTokenizer
from webconf_audit.local.nginx.parser.tokens import TokenType


def test_tokenize_simple_directive() -> None:
    tokens = NginxTokenizer("worker_processes 1;").tokenize()

    assert [token.token_type for token in tokens] == [
        TokenType.WORD,
        TokenType.WORD,
        TokenType.SEMICOLON,
        TokenType.EOF,
    ]
    assert [token.value for token in tokens] == [
        "worker_processes",
        "1",
        ";",
        "",
    ]


def test_tokenize_simple_block() -> None:
    text = "http {\n  server   {\n  }\n}\n"

    tokens = NginxTokenizer(text).tokenize()

    assert [token.token_type for token in tokens] == [
        TokenType.WORD,
        TokenType.LBRACE,
        TokenType.WORD,
        TokenType.LBRACE,
        TokenType.RBRACE,
        TokenType.RBRACE,
        TokenType.EOF,
    ]
    assert [token.value for token in tokens] == [
        "http",
        "{",
        "server",
        "{",
        "}",
        "}",
        "",
    ]


def test_tokenize_skips_comment_after_directive() -> None:
    text = "worker_processes 1; # comment\nhttp { }\n"

    tokens = NginxTokenizer(text).tokenize()

    assert [token.token_type for token in tokens] == [
        TokenType.WORD,
        TokenType.WORD,
        TokenType.SEMICOLON,
        TokenType.WORD,
        TokenType.LBRACE,
        TokenType.RBRACE,
        TokenType.EOF,
    ]
    assert tokens[3].value == "http"
    assert tokens[3].line == 2
    assert tokens[3].column == 1


def test_tokenize_comment_only_line() -> None:
    tokens = NginxTokenizer("# only comment\n").tokenize()

    assert [token.token_type for token in tokens] == [TokenType.EOF]
    assert tokens[0].line == 2
    assert tokens[0].column == 1


def test_tokenize_skips_comment_between_directives() -> None:
    text = "events { }\n# between blocks\nhttp { }\n"

    tokens = NginxTokenizer(text).tokenize()

    assert [token.token_type for token in tokens] == [
        TokenType.WORD,
        TokenType.LBRACE,
        TokenType.RBRACE,
        TokenType.WORD,
        TokenType.LBRACE,
        TokenType.RBRACE,
        TokenType.EOF,
    ]
    assert tokens[3].value == "http"
    assert tokens[3].line == 3
    assert tokens[3].column == 1


def test_tokenize_quoted_argument_in_directive() -> None:
    tokens = NginxTokenizer('root "/var/www/html";').tokenize()

    assert [token.token_type for token in tokens] == [
        TokenType.WORD,
        TokenType.WORD,
        TokenType.SEMICOLON,
        TokenType.EOF,
    ]
    assert [token.value for token in tokens] == [
        "root",
        "/var/www/html",
        ";",
        "",
    ]
    assert tokens[1].line == 1
    assert tokens[1].column == 6


def test_tokenize_quoted_argument_in_block() -> None:
    tokens = NginxTokenizer('location "/app path" { }').tokenize()

    assert [token.token_type for token in tokens] == [
        TokenType.WORD,
        TokenType.WORD,
        TokenType.LBRACE,
        TokenType.RBRACE,
        TokenType.EOF,
    ]
    assert [token.value for token in tokens] == [
        "location",
        "/app path",
        "{",
        "}",
        "",
    ]
    assert tokens[1].line == 1
    assert tokens[1].column == 10


def test_tokenize_quoted_string_with_spaces() -> None:
    tokens = NginxTokenizer('set "hello world value";').tokenize()

    assert [token.value for token in tokens] == [
        "set",
        "hello world value",
        ";",
        "",
    ]


def test_tokenize_single_quoted_argument_in_directive() -> None:
    tokens = NginxTokenizer(
        "add_header Content-Security-Policy 'default-src self';"
    ).tokenize()

    assert [token.token_type for token in tokens] == [
        TokenType.WORD,
        TokenType.WORD,
        TokenType.WORD,
        TokenType.SEMICOLON,
        TokenType.EOF,
    ]
    assert [token.value for token in tokens] == [
        "add_header",
        "Content-Security-Policy",
        "default-src self",
        ";",
        "",
    ]
    assert tokens[2].line == 1
    assert tokens[2].column == 36


def test_tokenize_single_quoted_string_with_escaped_quote() -> None:
    tokens = NginxTokenizer("set $value 'it\\'s fine';").tokenize()

    assert [token.value for token in tokens] == ["set", "$value", "it's fine", ";", ""]


def test_tokenize_unterminated_quoted_string() -> None:
    with pytest.raises(NginxParseError, match="Unterminated quoted string"):
        NginxTokenizer('root "/var/www/html;').tokenize()


def test_tokenize_unterminated_single_quoted_string_reports_start() -> None:
    with pytest.raises(NginxParseError, match="Unterminated quoted string") as exc_info:
        NginxTokenizer("add_header Content-Security-Policy 'default-src self;").tokenize()

    assert exc_info.value.line == 1
    assert exc_info.value.column == 36
