# authplane-sdk

[![PyPI](https://img.shields.io/pypi/v/authplane-sdk?style=flat-square&label=authplane-sdk)](https://pypi.org/project/authplane-sdk/)
[![Python versions](https://img.shields.io/pypi/pyversions/authplane-sdk?style=flat-square)](https://pypi.org/project/authplane-sdk/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

Framework-agnostic OAuth 2.1 JWT validation and token operations for Python resource servers.

## Install

```bash
pip install authplane-sdk
```

## Quickstart

```python
import asyncio
from authplane import ASCredentials, AuthplaneClient


async def main():
    client = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        auth=ASCredentials(client_id="my-resource", client_secret="s3cret"),
    )

    res = client.resource(
        resource="https://api.example.com",
        scopes=["read", "write"],
    )

    claims = await res.verify(incoming_jwt)
    print(claims.sub, claims.scopes)

    await client.aclose()


asyncio.run(main())
```

Call `await client.aclose()` on shutdown to stop background JWKS and metadata refresh tasks.

## Documentation

Full API reference, configuration options, error hierarchy, DPoP, token operations, introspection, token exchange, and advanced usage: **[User Guide](https://github.com/AuthPlane/python-sdk/blob/main/authplane/docs/user-guide.md)**.
