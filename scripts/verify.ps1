param(
    [switch]$RunE2ESmoke,
    [switch]$RunOperatorContractTests
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

try {
    $env:PYTHONDONTWRITEBYTECODE = "1"

    cargo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo check -p pecr-controller --features rlm
    python -B scripts/validate_workflows.py .github/workflows
    python -B scripts/validate_openapi.py
    python -B scripts/rlm/verify_vendor_rlm.py
    cargo run -p pecr-boundary-check
    cargo test --workspace --exclude e2e_smoke

    if ($RunE2ESmoke) {
        if (-not $env:PECR_TEST_DB_URL) {
            throw "Set PECR_TEST_DB_URL before using -RunE2ESmoke."
        }
        cargo test -p e2e_smoke -- --nocapture
    }

    $bash = Get-Command bash -ErrorAction SilentlyContinue
    if (-not $bash) {
        throw "bash is required to syntax-check scripts/ci.sh and scripts/perf/suite7.sh. Install Git Bash or use WSL."
    }
    bash -n scripts/ci.sh
    bash -n scripts/perf/suite7.sh

    python -B -m unittest discover -s scripts/tests -p "test_*.py"
    python -B -m unittest discover -s scripts/perf -p "test_*.py"
    python -B -m unittest discover -s scripts/ops -p "test_*.py"
    python -B scripts/replay/regression_gate.py `
        --store fixtures/replay/terminal_modes `
        --require-terminal-mode SUPPORTED `
        --require-terminal-mode INSUFFICIENT_EVIDENCE `
        --require-terminal-mode INSUFFICIENT_PERMISSION `
        --require-terminal-mode SOURCE_UNAVAILABLE

    if ($env:PECR_REPLAY_STORE_DIR) {
        python -B scripts/replay/regression_gate.py --store $env:PECR_REPLAY_STORE_DIR
    }

    $shouldRunContracts = $RunOperatorContractTests -or $env:PECR_RUN_OPERATOR_CONTRACT_TESTS -eq "1"
    if ($shouldRunContracts) {
        $args = @("-B", "scripts/replay/run_operator_contract_tests.py")
        if ($env:PECR_OPERATOR_CONTRACT_GATEWAY_URL) {
            $args += @("--gateway-url", $env:PECR_OPERATOR_CONTRACT_GATEWAY_URL)
        }
        if ($env:PECR_LOCAL_AUTH_SHARED_SECRET) {
            $args += @("--local-auth-secret", $env:PECR_LOCAL_AUTH_SHARED_SECRET)
        }
        python @args
    }

    python -B scripts/contracts/check_contract_lock.py
    python -B scripts/security/check_image_tags.py
}
finally {
    Pop-Location
}
