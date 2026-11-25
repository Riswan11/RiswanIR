# CI and security scanning

The workflows run on pull requests to main and pushes to main. Security and CodeQL also run on schedules. Main requires a pull request and up-to-date passing checks, including for repository admins. The required approving-review count is zero. CODEOWNERS identifies a maintainer.

| Required check | Workflow and controls | Artifacts |
| --- | --- | --- |
| Tests | [CI](../../.github/workflows/ci.yml) runs pytest on Python 3.11 and requires 90% branch-inclusive coverage | JUnit and coverage XML |
| Code quality | [CI](../../.github/workflows/ci.yml) runs Ruff format check, Ruff lint, Mypy and actionlint | Job logs |
| Security scans | [Security](../../.github/workflows/security.yml) runs Bandit at medium-or-higher, Gitleaks on Git history, pip-audit on resolved dependencies, and Trivy for high and critical vulnerabilities | Security JSON and runtime requirements |
| CodeQL analysis | [CodeQL](../../.github/workflows/codeql.yml) scans Python and fails on security severity 7 or higher | SARIF and code scanning alerts |
| Generate SBOM | [SBOM](../../.github/workflows/sbom.yml) inventories installed runtime packages with Syft and verifies core components are present | CycloneDX JSON |

Workflows pin actions to full commit SHAs and verify the release hashes of standalone scanners. Workflow tokens default to contents read. The CodeQL job also requests security-events write to publish results. GitHub secret scanning and push protection are enabled. Dependabot checks Python and Actions versions and can open security updates.

Review failures and artifacts before merge. Resolve the cause or follow the [exception process](../../SECURITY.md). Repository gates govern changes to source. The pipeline does not deploy a runtime. [Quality-gates ADR](../adr/0008-devsecops-quality-gates.md)
