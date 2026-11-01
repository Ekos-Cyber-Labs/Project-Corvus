"""Password-form coverage for the egress secret redactor.

Each case is a command-line password form common in attack chains that
``corvus.guardrails.egress.redact`` must catch: only the password is
replaced, surrounding user names, hosts, share paths and flags survive.
Near-miss benign text that merely looks similar stays byte-identical.
All secrets are synthetic (``# gitleaks:allow`` where a scanner-shaped
token appears).
"""

from __future__ import annotations

from corvus.guardrails.egress import redact

PW = "S3cret-Pass-9"  # gitleaks:allow

# (raw command, password fragment that must vanish, survivors kept verbatim)
PASSWORD_FORMS: list[tuple[str, list[str]]] = [
    (f"net user bob {PW} /add", ["net user", "bob", "/add"]),  # gitleaks:allow
    (f"net user bob {PW}", ["net user", "bob"]),  # gitleaks:allow
    (f'net user "Bob Smith" {PW} /add', ['"Bob Smith"', "/add"]),  # gitleaks:allow
    (
        f"net use Z: \\\\srv\\share {PW} /user:bob",  # gitleaks:allow
        ["net use", "Z:", "\\\\srv\\share", "/user:bob"],
    ),
    (
        f"net use \\\\srv\\share {PW} /user:corp\\bob",  # gitleaks:allow
        ["net use", "\\\\srv\\share", "/user:corp\\bob"],
    ),
    (
        f"net use \\\\h\\s /user:corp\\a {PW}",  # gitleaks:allow
        ["net use", "\\\\h\\s", "/user:corp\\a"],
    ),
    (
        f"schtasks /create /tn T /tr cmd /sc daily /RU bob /RP {PW}",  # gitleaks:allow
        ["schtasks", "/RU bob", "/RP"],
    ),
    (
        f"sqlcmd -S dbserver -U sa -P {PW}",  # gitleaks:allow
        ["sqlcmd", "-S dbserver", "-U sa"],
    ),
    (
        f"ldapsearch -x -D cn=reader -w {PW} -b dc=example,dc=com",  # gitleaks:allow
        ["ldapsearch", "-D cn=reader", "-w"],
    ),
    (
        f"xfreerdp /u:bob /p:{PW} /v:rdp.example.com",  # gitleaks:allow
        ["xfreerdp", "/u:bob", "/v:rdp.example.com"],
    ),
    (
        f"smbclient //srv/share -U bob%{PW}",  # gitleaks:allow
        ["smbclient", "//srv/share", "-U bob%"],
    ),
    (
        f"echo 'bob:{PW}' | chpasswd",  # gitleaks:allow
        ["echo", "bob:", "| chpasswd"],
    ),
    (
        f"echo bob:{PW} | chpasswd",  # gitleaks:allow
        ["echo", "bob:", "| chpasswd"],
    ),
    (
        f"openssl enc -d -aes256 -in f.enc -passin pass:{PW}",  # gitleaks:allow
        ["openssl", "-passin pass:"],
    ),
    (
        f"mysql://bob:{PW}@db.example.com:3306/app",  # gitleaks:allow
        ["mysql://", "@db.example.com:3306/app"],
    ),
    (
        f"postgresql://bob:{PW}@db.example.com/app",  # gitleaks:allow
        ["postgresql://", "@db.example.com/app"],
    ),
    (
        f"ftp://bob:{PW}@files.example.com/x",  # gitleaks:allow
        ["ftp://", "@files.example.com/x"],
    ),
    (
        f"redis://:{PW}@cache.example.com:6379/0",  # gitleaks:allow
        ["redis://", "@cache.example.com:6379/0"],
    ),
    (
        f"mongodb://bob:{PW}@mdb.example.com/db",  # gitleaks:allow
        ["mongodb://", "@mdb.example.com/db"],
    ),
    (
        f"amqp://bob:{PW}@mq.example.com/v",  # gitleaks:allow
        ["amqp://", "@mq.example.com/v"],
    ),
    (
        f"ldap://bob:{PW}@idp.example.com/dc",  # gitleaks:allow
        ["ldap://", "@idp.example.com/dc"],
    ),
    (
        f"smb://bob:{PW}@srv/share",  # gitleaks:allow
        ["smb://", "@srv/share"],
    ),
]

NT_PAIR = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def test_password_forms_redact_only_password() -> None:
    assert len(PASSWORD_FORMS) == 22
    for raw, survivors in PASSWORD_FORMS:
        out = redact(raw)
        assert PW not in out, raw
        assert "[REDACTED:" in out, raw
        for survivor in survivors:
            assert survivor in out, (raw, survivor)


def test_ntlm_lm_nt_pair_redacted() -> None:
    out = redact(f"sekurlsa::pth /user:a /nthash {NT_PAIR} /domain:x")
    assert "aad3b435" not in out
    assert "31d6cfe0" not in out
    assert "[REDACTED:hash]" in out
    assert "/user:a" in out


def test_ntlm_pair_near_miss_untouched() -> None:
    # 31 hex chars (one short) and non-hex pairs are not hash pairs.
    short = "a" * 31 + ":" + "b" * 31
    nonhex = "z" * 32 + ":" + "q" * 32
    assert redact(f"token {short} end") == f"token {short} end"
    assert redact(f"token {nonhex} end") == f"token {nonhex} end"


NEAR_MISS = [
    "net user bob /add",
    "net user bob /delete",
    "net user /add",
    "net user help",
    "net use Z: \\\\srv\\share",
    "net use \\\\srv\\share",
    "net use /delete",
    "net use Z: /delete",
    "schtasks /query /tn T",
    "schtasks /create /tn T /tr cmd /sc daily /RU bob",
    "sqlcmd -S dbserver -U sa",
    'curl -w "%{http_code}" https://example.com/',
    "smbclient //srv/share -U bob",
    "xfreerdp /u:bob /v:rdp.example.com",
    "xfreerdp /u:bob /pth:31d6cfe0d16ae931b73c59d7e0c089c0 /v:h",
    "echo hello | chpasswd",
    "echo user:pass | grep pass",
    "openssl enc -d -aes256 -in f.enc -passin file:cert.pem",
    "mysql://db.example.com/app",
    "ftp://files.example.com/x",
    "redis://cache.example.com:6379/0",
    "net use status",
]


def test_near_miss_benign_untouched() -> None:
    assert len(NEAR_MISS) == 22
    for text in NEAR_MISS:
        assert redact(text) == text, text


def test_password_forms_idempotent() -> None:
    for raw, _ in PASSWORD_FORMS:
        once = redact(raw)
        assert redact(once) == once, raw
    assert redact(redact(NT_PAIR)) == redact(NT_PAIR)
