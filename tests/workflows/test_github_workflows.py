import os
import subprocess
from pathlib import Path


def test_sdk_tests_workflow_runs_each_available_sdk_test_suite() -> None:
    workflow = Path(".github/workflows/sdk-tests.yml")

    text = workflow.read_text(encoding="utf-8")

    assert "name: SDK 测试与兼容性证明" in text
    assert "python-sdk-tests:" in text
    assert "node-sdk-tests:" in text
    assert "cross-sdk-compatibility:" in text
    assert "kotlin-sdk-tests:" in text
    assert "kotlin-cross-sdk-compatibility:" in text
    assert "prove-sdk-interoperability:" in text
    assert "sdk-examples:" in text
    assert '"sdk/kotlin/**"' in text
    assert '"examples/**"' in text
    assert "uv run pytest tests/py/test_v1_foundation.py -q" in text
    assert "npm ci" in text
    assert "npm run build" in text
    assert (
        "uv run pytest tests/compat/test_cross_language.py::test_node_sdk_exposes_v1_datalock_surface"
        in text
    )
    assert (
        "uv run pytest tests/compat/test_cross_language.py::test_each_sdk_can_open_envelopes_locked_by_every_sdk -q"
        in text
    )
    assert "gradle test" in text
    assert "uv run pytest tests/kotlin/test_kotlin_sdk.py -q" in text
    assert "uv run pytest tests/examples/test_sdk_examples.py -q" in text
    assert text.count("npm ci") == 4
    assert text.count("npm run build") == 4


def test_keyring_check_workflow_builds_node_cli_before_using_it() -> None:
    workflow = Path(".github/workflows/keyring-check.yml")

    text = workflow.read_text(encoding="utf-8")

    assert "node sdk/node/hx-datalock.mjs verify-keyring" in text
    assert "npm ci" in text
    assert "npm run build" in text


def test_keyring_check_workflow_makes_missing_keyring_skip_explicit() -> None:
    workflow = Path(".github/workflows/keyring-check.yml")

    text = workflow.read_text(encoding="utf-8")

    assert "Keyring validation skipped: no keyring.hxdl.json is committed in this repository." in text
    assert "This check did not validate a Keyring document." in text
    assert "Raw private key scan skipped: no keyring.hxdl.json is committed in this repository." in text
    assert "bash scripts/refuse-public-keyring.sh" in text


def test_public_repository_refuses_a_committed_keyring(tmp_path: Path) -> None:
    script = Path("scripts/refuse-public-keyring.sh")
    text = script.read_text(encoding="utf-8")
    workflow = Path(".github/workflows/keyring-private.yml").read_text(encoding="utf-8")

    assert "A Keyring must never be committed to a public GitHub repository." in text
    assert "bash scripts/refuse-public-keyring.sh" in workflow

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess_env = {
        "GIT_AUTHOR_NAME": "hxdl",
        "GIT_AUTHOR_EMAIL": "hxdl@example.com",
        "GIT_COMMITTER_NAME": "hxdl",
        "GIT_COMMITTER_EMAIL": "hxdl@example.com",
    }

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=repo, check=True, env={**os.environ, **subprocess_env})

    git("init")
    (repo / "keyring.hxdl.json").write_text('{"schema": "hxdl.keyring.v1"}\n', encoding="utf-8")
    git("add", "keyring.hxdl.json")

    public = subprocess.run(
        ["bash", str(script.resolve())],
        cwd=repo,
        text=True,
        capture_output=True,
        env={**os.environ, "REPO_PRIVATE": "false", "REPO_VISIBILITY": "public"},
        check=False,
    )
    assert public.returncode != 0
    assert "must never be committed to a public GitHub repository" in public.stdout

    private = subprocess.run(
        ["bash", str(script.resolve())],
        cwd=repo,
        text=True,
        capture_output=True,
        env={**os.environ, "REPO_PRIVATE": "true", "REPO_VISIBILITY": "private"},
        check=False,
    )
    assert private.returncode == 0, private.stdout + private.stderr

    empty = tmp_path / "empty"
    empty.mkdir()
    subprocess.run(["git", "init"], cwd=empty, check=True)
    clear = subprocess.run(
        ["bash", str(script.resolve())],
        cwd=empty,
        text=True,
        capture_output=True,
        env={**os.environ, "REPO_PRIVATE": "false", "REPO_VISIBILITY": "public"},
        check=False,
    )
    assert clear.returncode == 0, clear.stdout + clear.stderr
    assert "No Keyring document is committed." in clear.stdout
