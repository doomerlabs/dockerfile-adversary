# Contributing

## Prerequisites

- Node.js 22
- The Adversary CLI

## Setup and validation

```sh
npm ci
npm test
doomer validate .
doomer pack --check .
```

`npm test` builds the runtime before running the test suite.

## Adding or changing review behavior

1. Keep deterministic checks evidence-backed and parse repository files without
   executing target code.
2. Update the runtime rule or review definition.
3. Add focused vulnerable and clean fixtures or equivalent review calibration.
4. Add tests for detection, non-detection, evidence, and stable ordering.
5. Keep the compact inventory in `CHECKS.md` aligned with shipped behavior.
