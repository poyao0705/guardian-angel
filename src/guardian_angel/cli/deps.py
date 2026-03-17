from __future__ import annotations


def require_cli_dependencies():
    try:
        import rich  # noqa: F401
        import typer  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "Install CLI extras: pip install guardian-angel[cli]"
        ) from exc