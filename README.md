# Authflow origin

Put your MCP server behind Authflow with the origin proxy sidecar, or copy a verifier into a TypeScript or Python server. Both check Origin Protocol v1 before your MCP handles a request. Authflow handles customer sign-in and access at the gateway.

| Your server | Use |
| --- | --- |
| Any language; you can run a container | The `authflow-origin-proxy` image. Keep the upstream reachable only through the proxy. |
| TypeScript on Node 24+ or Cloudflare Workers with Web Crypto Ed25519 | Copy [`authflow-origin-verifier.ts`](https://github.com/authflow-ai/authflow-origin/blob/v1.0.1/verifiers/authflow-origin-verifier.ts). Wire it into your request handler and an atomic replay store. |
| Python 3.11 or later | Copy [`authflow_origin_verifier.py`](https://github.com/authflow-ai/authflow-origin/blob/v1.0.1/verifiers/authflow_origin_verifier.py). Install `cryptography`, then wire the verifier into your request handler and an atomic replay store. |

These are copyable source files, not npm or PyPI packages. Keep the version you copied with your application and review later releases before replacing it. The [Origin Protocol v1 specification](https://docs.authflow.ai/docs/protocol/v1) defines the wire contract.

## Quick start with the proxy

Get the exact `issuer` and canonical `resource` from your MCP’s registration receipt. Register the proxy’s base URL as `origin_base_uri`; the gateway adds `/mcp`, so the base URL must not end in `/mcp`.

```sh
docker pull ghcr.io/authflow-ai/authflow-origin-proxy:1.0.1
docker run -p 8080:8080 \
  -e Authflow__Issuer="$AUTHFLOW_ISSUER" \
  -e Authflow__Resource="$AUTHFLOW_RESOURCE" \
  -e Authflow__UpstreamBaseUri=http://upstream:3000 \
  -e Authflow__SingleReplica=true \
  ghcr.io/authflow-ai/authflow-origin-proxy:1.0.1
```

The upstream name must resolve on your container network. Expose only the proxy to incoming traffic. The image listens on port 8080; `GET /healthz` is its container health endpoint. For production, replace the version tag with the release’s verified `ghcr.io/authflow-ai/authflow-origin-proxy@sha256:…` reference.

## Configuration

| Environment variable | Meaning |
| --- | --- |
| `Authflow__Issuer` | The receipt’s exact issuer, without a trailing slash. |
| `Authflow__Resource` | The receipt’s exact canonical resource URI. It stays fixed when your MCP moves to another public hostname. |
| `Authflow__UpstreamBaseUri` | Your upstream MCP server’s private base URL. |
| `Authflow__SingleReplica` | Set `true` only when exactly one proxy replica runs without Redis. |
| `Authflow__NonceCacheRedis` | Shared Redis connection string. Required before running multiple proxy replicas. Store it as a deployment secret. |

The proxy validates issuer and resource spelling at startup. Copy them from the receipt; do not normalize or reconstruct them.

## Nonce cache and scaling out

Every accepted identity consumes its nonce until its expiry plus 60 seconds. Without Redis, the proxy uses a process-local store and refuses to start unless `Authflow__SingleReplica=true` declares one replica. Before scaling, configure `Authflow__NonceCacheRedis`; the proxy then uses atomic `SET NX` claims across replicas and ignores the single-replica flag.

A replay-store failure rejects the request with `replay_cache_unavailable`. Never fall back to a local cache or disable replay checks during an outage.

## Forwarded-header contract

After verification the proxy strips `X-Authflow-Identity` and replaces any client-supplied plain Authflow headers with:

| Header | Verified value |
| --- | --- |
| `X-Authflow-User` | `sub` |
| `X-Authflow-Tier` | `tier` |
| `X-Authflow-Nonce` | `nonce`, also used as `identity_nonce` in origin-reported usage |

Trust these headers only when the proxy is the sole way to reach the upstream. Missing or invalid identity gets HTTP 403 with `error=invalid_origin_identity` and an `error_code`; there is no `WWW-Authenticate` challenge. Rejections also identify the implementation in `X-Authflow-Verifier`.

## Copy a verifier

Copy the whole versioned file unchanged. Its comments describe the request adapter, result and replay-store interface. Create one verifier per running process or isolate so key caching and refresh throttling survive across requests. Configure the exact receipt issuer and resource.

For TypeScript, use `createOriginVerifier({ issuer, resource, replayStore })`, then `await verifier.verify(request.headers)`. Node handlers that expose raw headers should pass all `X-Authflow-Identity` field values as an array; never silently select the first of duplicate fields. On failure, return the result’s `response` unchanged. On success, use only the verified `identity`.

For Python, install `cryptography` and create `OriginVerifier(issuer=issuer, resource=resource, replay_store=store)`. Pass all raw identity field values to `await verifier.verify(values)`. On `OriginVerificationError`, return its `status_code`, `body` and `headers`; on success, use the returned `VerifiedIdentity`. An ASGI adapter should collect the identity values from `scope["headers"]`, preserving duplicates.

Both stores implement an asynchronous `claim(key, retain_until)` operation: atomically insert the supplied key only when absent, keep it through the supplied Unix expiry second, and return whether the insert succeeded. All replicas must use the same store. Store errors must raise, so verification fails closed.

**Cloudflare Workers:** use a Durable Object that serializes each nonce’s claim and expiry, or another store with an atomic conditional insert. A Workers KV `get` followed by `put` is not atomic and cannot prevent replay. A process-local map also cannot protect multiple isolates. The verifier handles key discovery, signatures and claim checks; the replay store and HTTP adapter remain your application’s responsibility.

For a paid `origin_reported` MCP, your application also implements the [usage reporting contract](https://docs.authflow.ai/docs/protocol/v1#7-usage-reporting-endpoint). Neither the proxy nor these verifiers debit credits. Free and `gateway_metered` MCPs need no origin billing credential.

## For agents

1. Use the Authflow MCP’s `authflow_integration_plan` for the resource and framework (`proxy`, `typescript` or `python`).
2. Choose the image or exact versioned verifier file above. Copy the complete verifier and wire an atomic replay store; do not replace verification with a signature-only snippet.
3. Verify identity on every `/mcp` request before handling it. Never return 401 from the origin or send a payment URL in tool output.
4. Send an unsigned request and confirm 403 without `WWW-Authenticate`. Test replay and a replay-store outage as well.
5. Run `authflow_doctor`, then `authflow_verify_resource`. Resolve the reported checks and obtain the owner’s approval before publishing their MCP. Give customers only the gateway URL.

## Source and image releases

This repository contains only the source creators use: this guide, the licence and changelog, proxy source, two verifier files and the image-release workflow. It is a distribution repository; changes arrive through Authflow’s approved publisher. Direct branch changes and release-tag changes are restricted by repository rules.

Each `vX.Y.Z` release tag builds the proxy image from [`proxy/Dockerfile`](https://github.com/authflow-ai/authflow-origin/blob/v1.0.1/proxy/Dockerfile) using this repository’s source and publishes it to GHCR. To build a checked-out release locally:

```sh
docker build -f proxy/Dockerfile -t authflow-origin-proxy .
```

See [release tags](https://github.com/authflow-ai/authflow-origin/tags) and the [changelog](https://github.com/authflow-ai/authflow-origin/blob/main/CHANGELOG.md). Report security vulnerabilities privately to [security@authflow.ai](mailto:security@authflow.ai), with a minimal reproduction and the affected version. Do not include credentials or customer data in a public issue.

Copyright 2026 Authflow LLC. Licensed under [Apache-2.0](https://github.com/authflow-ai/authflow-origin/blob/main/LICENSE).
