# Contributing to CloudOS

Thank you for your interest in contributing to CloudOS. This document explains how to set up your environment, coding standards, testing requirements, and the review process so that your contributions can be merged efficiently.

Contents
- Code of Conduct
- Getting Started
- Building and Testing
- Contribution Workflow
- Coding Standards
- Commit Message Conventions
- Pull Request Requirements
- Testing Requirements
- Performance & Quality Gates
- Documentation Requirements
- Security & Responsible Disclosure
- Style, Linters, and Formatting
- License

## Code of Conduct

By participating, you agree to uphold our Code of Conduct.
- See: CODE_OF_CONDUCT.md

## Getting Started

1) Fork the repository on GitHub and create a feature branch:
```bash
git clone https://github.com/Abhishekpan731/cloudOS.git
cd cloudOS
git checkout -b feature/short-descriptor
```

2) Familiarize yourself with the repository structure and design docs:
- README.md (quick start, architecture overview)
- design/high-level/system-overview/system-overview.md
- design/low-level/modules/ (deep-dive per module)
- docs/ (microkernel & cloud architecture, runbooks)

3) For substantial proposals, open a GitHub Discussion or Issue first to get early feedback.

## Building and Testing

Primary build:
```bash
./test_compile.sh
```

Comprehensive test suite:
```bash
./tests/test_all.sh
```

Artifacts:
- Kernel modules: kernel/* and kernel/include/kernel/*
- Design docs: design/*
- Operator docs: docs/*
- Scripts: scripts/*

Toolchains:
- GCC/Clang with C99 support
- POSIX shell environment
- Optional: Docker, QEMU

## Contribution Workflow

1) Open/upvote an Issue (bug/feature/design) to align on scope and approach.
2) Create a feature branch from main.
3) Implement changes with tests and docs.
4) Run:
   - ./test_compile.sh
   - ./tests/test_all.sh
5) Push your branch and open a Pull Request (PR).
6) Address review feedback; ensure checks pass.
7) Squash commits if requested; maintain a clean history.

Tip: Keep PRs focused and small. Separate refactors from feature changes where possible.

## Coding Standards

Language & Standards:
- C99 (kernel and modules)
- Treat warnings as errors (Werror philosophy via build script)

Subsystem boundaries:
- Respect interfaces in kernel/include/kernel/*.h
- Avoid circular dependencies; initialize subsystems from kernel/kernel.c or via registrars
- Keep the microkernel core minimal; isolate higher-level features into modules

Memory & Safety:
- Match every allocation with a free (kmalloc/kfree)
- Avoid unbounded stack usage; prefer static buffers carefully
- Zero sensitive memory (see secure clear helpers)

Error Handling:
- Return explicit error codes; avoid silent failure
- Log via kernel console where appropriate (kprintf/structured logs in future)

Portability:
- Keep code portable between x86_64 and ARM64 HALs where feasible

## Commit Message Conventions

Use Conventional Commits for clarity and tooling compatibility:
- feat: short description (new feature)
- fix: short description (bug fix)
- docs: update to documentation
- refactor: code change that neither fixes a bug nor adds a feature
- perf: performance improvement
- test: add or update tests
- build/chore/ci: meta changes

Examples:
- feat(fs): add B-tree delete balancing
- fix(net): correct ARP cache eviction logic
- docs(README): add compatibility matrix
- test(security): add MAC label tests

Limit subject to ~72 chars; provide a detailed body when necessary.

## Pull Request Requirements

- Description: What, why, how; link relevant Issues.
- Scope: Keep PRs focused; split unrelated changes.
- Tests: Add/extend tests for new/changed behavior.
- Docs: Update README/FEATURES/ROADMAP or design docs as appropriate.
- Checks: All CI/scripts must pass (compilation & tests).
- Performance: Do not regress performance; include before/after notes if relevant.

PR Checklist:
- [ ] Compiles via ./test_compile.sh
- [ ] Tests pass via ./tests/test_all.sh
- [ ] Docs updated (if user-visible change)
- [ ] Conventional commit messages
- [ ] No unrelated changes

## Testing Requirements

Minimum expectations:
- Compilation succeeds (no warnings-as-errors)
- Functional coverage for the subsystem you touch (extend tests/test_all.sh or add targeted tests)
- Regression protection: If you fix a bug, add a test to prevent recurrence

Where feasible, prefer:
- Unit-like tests or scripted validations for deterministic behavior
- Integration checks across subsystems (e.g., VFS + CloudFS)
- Performance sanity checks (see Performance & Quality Gates)

## Performance & Quality Gates

- No significant regressions to:
  - Compilation time (dev baseline ~742 ms)
  - Kernel object size (~224 KB reference)
  - Filesystem throughput (NVMe > 2 GB/s synthetic)
  - TCP throughput (> 1 Gbps synthetic)
  - Core services memory (< 50 MB synthetic)
- If a change may affect performance, include brief measurements and methodology.

## Documentation Requirements

Update docs when:
- Adding/modifying user-visible behavior (README, FEATURES, ROADMAP)
- Changing architecture or design assumptions (design/high-level/*, design/low-level/*)
- Introducing new operational procedures (docs/operations-guide.md, runbooks)

Prefer concise README sections and link deeper content to design/ docs.

## Security & Responsible Disclosure

- Do not include exploit details in public Issues/PRs.
- For vulnerabilities, follow SECURITY.md and coordinate privately.
- Avoid introducing cryptographic primitives without review; where possible rely on vetted libraries (note: current in-tree primitives are simplified/scaffolded).

## Style, Linters, and Formatting

- C: Keep code consistent with surrounding style (K&R-like)
- Headers: place interfaces in kernel/include/kernel/
- Names: use clear prefixes per subsystem; avoid global symbol conflicts
- If/when a .clang-format or lint config is introduced, adhere to it

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
- See: LICENSE

Thank you for contributing to CloudOS!
