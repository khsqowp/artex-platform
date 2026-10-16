# ARTEx

[한국어](README.md) · English · [日本語](README.ja.md) · [简体中文](README.zh.md)

**ARTEx** is a locally deployable security assessment platform with a Go service and a Next.js web interface. This repository contains a cleaned source snapshot prepared for independent GitHub publication.

> Use ARTEx only on systems you own or have explicit written permission to assess. Start with an isolated lab such as OWASP Juice Shop. Define and verify the authorized scope before enabling any request-capable feature.

## Purpose and responsibility

This project is intended to support security assessment, maintenance, and incident preparedness and response for services I develop or operate, or am expressly authorized to assess. Use it only on systems you own or operate, or for which you have prior written authorization, and only within the approved scope. Work-related use must comply with your organization's policies and approvals. Publication or download does not grant permission to test third-party systems.

The user is responsible for selecting the target, obtaining and verifying authorization, configuring scope and safeguards, complying with applicable law and third-party terms, and for all consequences of use. The maintainers do not direct, authorize, monitor, or endorse any user's activity and have no control over downstream use.

The software is provided **“AS IS”**, without warranties, to the maximum extent permitted by applicable law. To the same extent, the maintainers disclaim liability for claims, losses, or damages arising from use or inability to use the software. Nothing in this notice excludes or limits liability that cannot lawfully be excluded or changes rights and obligations imposed by the included license or applicable law.

This notice states the project's intended allocation of responsibility; it is not a guarantee that a maintainer cannot be investigated, sued, or held responsible. Legal outcomes depend on the facts, jurisdiction, conduct, and applicable law. No use of this software is authorized merely by this publication.

## What is included

- Go service and supporting packages
- Next.js web client
- Docker Compose deployment configuration and development scripts
- Example configuration files and the repository's AGPL-3.0 license

Runtime databases, local credentials, `.env` files, logs, generated build output, and assessment-specific materials are excluded. The `.env.example` contains placeholders; configure your own deployment values before starting services.

## Run with Docker Compose

1. Install Docker Desktop with Compose support.
2. Copy `.env.example` to `.env` and replace `POSTGRES_PASSWORD` with a strong local value. Add an LLM provider key only if you intend to use ARTEx's native LLM features.
3. Start the services with `docker compose up -d`.
4. Open `http://127.0.0.1:8787`.

The Compose file uses the published ARTEx container image by default. Building this source snapshot instead requires following the included Dockerfile and build scripts; review their configuration before deployment. Do not expose the service publicly without adding appropriate authentication, network restrictions, and operational safeguards.

## Development

The source includes Go and web-client projects. See `go.mod`, the `web/` package scripts, `build.sh`, and `dev.sh` for the project-specific development workflow. Required toolchain versions and build behavior can vary; confirm them in the project files before building.

## Claude Desktop integration

Claude Desktop connectors and agent profiles are maintained separately in the Claude integration repository. They connect to an operator-configured ARTEx instance; installing the plugin does not install or start this server. Configure both projects using their respective setup instructions.

## Provenance and license

This is a source snapshot with a newly initialized Git history, not a continuation of the upstream repository history. Review preserved source attribution and the included `LICENSE` before redistribution. Check release/update settings and all deployment defaults before publishing or operating a fork.

The responsibility notice above supplements the included AGPL-3.0 license; it does not replace or amend that license.
