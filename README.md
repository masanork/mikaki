# Mikaki

Mikaki is an experimental passkey identity service built primarily in Rust. It combines a portable WebAuthn verifier with a shared account and OpenID Connect login for applications. Encrypted personal data and user-controlled sharing are being developed separately.

> **Development prototype:** The OP Worker and one administrator account are deployed, but no production relying party is registered. Do not use Mikaki to protect real user accounts. See [project status](docs/status.md) for verified behavior and release gaps.

## Start here

| Task | Guide |
| --- | --- |
| Run locally | [Getting started](docs/getting-started.md) |
| Integrate an application | [RP integration](docs/rp-integration.md) |
| Understand the design | [Architecture](docs/architecture.md) and [decisions](docs/adr/README.md) |
| Operate a deployment | [Cloudflare deployment](docs/cloudflare-deployment.md) |
| Browse current and proposed work | [Documentation](docs/README.md) and [roadmap](docs/roadmap.md) |

Changes are recorded in the [changelog](CHANGELOG.md). Report vulnerabilities through the [security policy](SECURITY.md). The project is available under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

## Project metrics

The charts track implementation and test code size and native Rust coverage. See the [measurement scope](metrics/README.md) and [dependency inventory](metrics/dependency-inventory.md) for what they include.

![Codebase growth: implementation and test source lines](metrics/code-size.svg)

![Native Rust coverage over time](metrics/coverage.svg)
