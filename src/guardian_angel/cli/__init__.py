from .deps import require_cli_dependencies
from .evaluate import evaluate_files, load_request
from .output import render_decision, render_verbose_context


def create_app():
	from .app import create_app as _create_app

	return _create_app()


def main():
	from .app import main as _main

	return _main()


def __getattr__(name: str):
	if name == "app":
		from .app import app as _app

		return _app
	raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
	"app",
	"create_app",
	"evaluate_files",
	"load_request",
	"main",
	"render_decision",
	"render_verbose_context",
	"require_cli_dependencies",
]
