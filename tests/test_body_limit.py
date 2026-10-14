from threatfusion.body_limit import BodyLimitMiddleware


async def test_chunked_body_cannot_bypass_limit():
    called = []
    sent = []

    async def app(scope, receive, send):
        called.append(True)

    chunks = iter(
        [
            {"type": "http.request", "body": b"x" * 5000, "more_body": True},
            {"type": "http.request", "body": b"x" * 5000, "more_body": False},
        ]
    )

    async def receive():
        return next(chunks)

    async def send(message):
        sent.append(message)

    await BodyLimitMiddleware(app)(
        {"type": "http", "method": "POST", "path": "/api/analyze", "headers": []}, receive, send
    )
    assert not called and sent[0]["status"] == 413
