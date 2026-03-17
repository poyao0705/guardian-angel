from __future__ import annotations
from importlib.metadata import version as package_version

from .deps import require_cli_dependencies
from .evaluate import evaluate_request, load_request
from .output import render_decision, render_verbose_context

require_cli_dependencies()
import typer


def create_app():
    cli_app = typer.Typer(help="GuardianAngel CLI")

    def version_callback(value: bool):
        if value:
            print(package_version("guardian-angel"))
            raise typer.Exit()

    @cli_app.callback()
    def callback(
        ctx: typer.Context,
        version: bool = typer.Option(
            False, "--version", "-v", callback=version_callback, is_eager=True,
            help="Show version and exit.",
        ),
        verbose: bool = typer.Option(
            False,
            "--verbose",
            help="Show additional evaluation context.",
        ),
    ):
        """GuardianAngel CLI entry point."""
        ctx.obj = {"verbose": verbose}

    @cli_app.command()
    def evaluate(
        ctx: typer.Context,
        policy: str = typer.Argument(..., help="Path to policy YAML file."),
        request: str = typer.Argument(..., help="Path to action request JSON file."),
        explain: bool = typer.Option(
            False,
            "--explain",
            help="Show the matched rule and decision reason.",
        ),
    ):
        """Evaluate a policy against an action request."""
        verbose = bool(ctx.obj and ctx.obj.get("verbose"))
        loaded_request = load_request(request)
        if verbose:
            render_verbose_context(
                policy_path=policy,
                request_path=request,
                request=loaded_request,
            )
        decision = evaluate_request(policy, loaded_request)
        render_decision(decision, explain=explain)
        
    return cli_app


app = create_app()


def main():
    app()
