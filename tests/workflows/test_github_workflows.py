from pathlib import Path


def test_sdk_tests_workflow_runs_each_available_sdk_test_suite() -> None:
    workflow = Path(".github/workflows/sdk-tests.yml")

    text = workflow.read_text(encoding="utf-8")

    assert "name: SDK Tests" in text
    assert "python-sdk-tests:" in text
    assert "node-sdk-tests:" in text
    assert "cross-sdk-compatibility:" in text
    assert "kotlin-sdk-tests:" in text
    assert "kotlin-cross-sdk-compatibility:" in text
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
    assert "uv run pytest tests/compat/test_cross_language.py -q" in text
    assert "gradle test" in text
    assert "uv run pytest tests/kotlin/test_kotlin_sdk.py -q" in text
    assert "uv run pytest tests/examples/test_sdk_examples.py -q" in text
    assert text.count("npm ci") == 3
    assert text.count("npm run build") == 3


def test_keyring_check_workflow_builds_node_cli_before_using_it() -> None:
    workflow = Path(".github/workflows/keyring-check.yml")

    text = workflow.read_text(encoding="utf-8")

    assert "node sdk/node/hx-datalock.mjs verify-keyring" in text
    assert "npm ci" in text
    assert "npm run build" in text
