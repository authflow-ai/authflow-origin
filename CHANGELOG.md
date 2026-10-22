# Changelog

## 1.0.1

- Add a manual image-build recovery path for an existing release tag, including explicit first-package initialization.
- Keep published versions immutable. Proxy and verifier behavior is unchanged apart from the reported implementation version.

## 1.0.0

- **Proxy:** Publish the Origin Protocol v1 proxy source and container image from `authflow-ai/authflow-origin`.
- **TypeScript:** Add a copyable verifier with key discovery, strict identity verification and an atomic replay-store interface.
- **Python:** Add a copyable verifier with the same protocol checks and replay-store contract.
- **Diagnostics:** Identify proxy and verifier versions on rejected requests through `X-Authflow-Verifier`.

The Origin Protocol v1 wire format is unchanged.
