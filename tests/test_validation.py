import pytest

from threatfusion.validation import validate


@pytest.mark.parametrize(
    "value,kind,normalized",
    [
        ("8.8.8.8", "ipv4", "8.8.8.8"),
        ("2001:4860:4860:0000::8888", "ipv6", "2001:4860:4860::8888"),
        ("Example.COM.", "domain", "example.com"),
        ("bücher.de", "domain", "xn--bcher-kva.de"),
        ("HTTPS://Example.COM/a?b=1#fragment", "url", "https://example.com/a?b=1"),
        ("https://[2001:4860::1]:443", "url", "https://[2001:4860::1]:443/"),
        ("A" * 32, "md5", "a" * 32),
        ("B" * 40, "sha1", "b" * 40),
        ("C" * 64, "sha256", "c" * 64),
    ],
)
def test_types(value, kind, normalized):
    ioc = validate(value)
    assert ioc.type.value == kind
    assert ioc.value == normalized


@pytest.mark.parametrize(
    "value",
    [
        "",
        "999.2.3.4",
        "01.2.3.4",
        "abc",
        "-bad.com",
        "bad_.com",
        "a..com",
        "ftp://example.com/a",
        "https://user:pass@example.com",
        "https://example.com:99999",
        "https://example.com/a b",
        "https://example.com\\evil",
        "fe80::1%eth0",
        "a" * 64 + ".com",
        "abc\x00.com",
        "https://",
        "https://127.000.0.1",
        "123.456",
        "https://%31%32%37.0.0.1",
    ],
)
def test_invalid(value):
    with pytest.raises(ValueError):
        validate(value)


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.1",
        "127.0.0.1",
        "::1",
        "fe80::1",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "203.0.113.42",
        "2001:db8::1",
        "service.internal",
        "https://192.168.1.1/",
        "https://[::ffff:127.0.0.1]/",
        "suspicious.example",
    ],
)
def test_nonpublic(value):
    assert not validate(value).public
