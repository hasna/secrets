# @hasna/secrets

A local secrets vault for AI agents — store API keys, passwords, tokens, and any credentials

[![npm](https://img.shields.io/npm/v/@hasna/secrets)](https://www.npmjs.com/package/@hasna/secrets)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

## Install

```bash
npm install -g @hasna/secrets
```

## CLI Usage

```bash
secrets --help
```

## Cloud Sync

This package supports cloud sync via `@hasna/cloud`:

```bash
cloud setup
cloud sync push --service secrets
cloud sync pull --service secrets
```

## Data Directory

Data is stored in `~/.hasna/secrets/`.

## License

Apache-2.0 -- see [LICENSE](LICENSE)
