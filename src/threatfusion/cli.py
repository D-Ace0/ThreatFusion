import asyncio
import ipaddress
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from .config import Settings
from .demo import fixtures
from .reports import pdf_report
from .service import Fusion
from .storage import Store
from .validation import validate

app = typer.Typer(no_args_is_help=True, help="ThreatFusion: privacy-conscious threat intelligence")
console = Console()


def show(result):
    s = result.score
    console.print(f"[bold cyan]ThreatFusion[/] | {result.mode.upper()} | {result.id}")
    console.print(result.ioc.value, markup=False)
    console.print(
        f"Risk: {s.risk if s.risk is not None else 'Unknown'} / 100 ({s.label}) | Confidence: {s.confidence}% | Coverage: {s.coverage}% | Freshness: {s.freshness}%"
    )
    table = Table("Provider", "Status", "Cache", "Evidence")
    for r in result.results:
        table.add_row(
            r.source,
            r.status,
            "hit" if r.cached else "-",
            "; ".join(f"{e.metric}={e.value:g}" for e in r.evidence) or r.message,
        )
    console.print(table)
    for c in s.contributions:
        console.print(f"  +{c.points:g} {c.source}: {c.reason}", markup=False)
    console.print("[yellow]Unvalidated heuristic, not a verdict. Demo evidence is synthetic.[/]")


async def run(value, settings, allow_url=False, refresh=False):
    async with httpx.AsyncClient(trust_env=False) as client:
        return await Fusion(settings, client).analyze(value, allow_url, refresh)


@app.command("validate")
def validate_command(value: str):
    """Validate locally without network access or storage."""
    try:
        console.print_json(validate(value).model_dump_json())
    except ValueError as exc:
        console.print(str(exc), markup=False)
        raise typer.Exit(2) from exc


@app.command()
def analyze(
    value: str,
    live: bool = typer.Option(False, help="Use configured real providers"),
    allow_url: bool = typer.Option(False, help="Authorize disclosure of full URL to providers"),
    refresh: bool = False,
    json_output: bool = typer.Option(False, "--json"),
    output: Path | None = typer.Option(None, help="Export .json or .pdf"),
):
    """Enrich an IOC. Demo follows .env unless --live is passed."""
    settings = Settings()
    if live:
        settings.demo = False
    if output and output.suffix.lower() not in (".json", ".pdf"):
        raise typer.BadParameter("Output must end in .json or .pdf")
    try:
        result = asyncio.run(run(value, settings, allow_url, refresh))
    except ValueError as exc:
        console.print(str(exc), markup=False)
        raise typer.Exit(2) from exc
    if json_output:
        typer.echo(result.model_dump_json(indent=2))
    else:
        show(result)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(
            pdf_report(result)
            if output.suffix.lower() == ".pdf"
            else result.model_dump_json(indent=2).encode()
        )


@app.command()
def demo():
    """Analyze every packaged fixture with no keys or network access."""
    settings = Settings(demo=True)
    for value in fixtures()["indicators"]:
        show(asyncio.run(run(value, settings)))


@app.command()
def history(limit: int = typer.Option(20, min=1, max=100)):
    """List local analysis history."""
    for result in Store(Settings().db_path).history(limit):
        console.print(
            f"{result.id} | {result.created_at.isoformat()} | {result.ioc.value}", markup=False
        )


@app.command("clear-history")
def clear_history(
    yes: bool = typer.Option(False, "--yes", help="Confirm deletion of all local history/cache"),
):
    if not yes:
        raise typer.BadParameter("Use --yes to confirm local history/cache deletion")
    Store(Settings().db_path).clear()
    console.print("Local history and cache cleared")


@app.command()
def serve(host: str = "127.0.0.1", port: int = typer.Option(8000, min=1, max=65535)):
    """Start the dashboard and API. Loopback by default."""
    import uvicorn

    from .api import create_app

    settings = Settings()
    try:
        local = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = False
    if not local and not settings.api_key.get_secret_value():
        raise typer.BadParameter("Set THREATFUSION_API_KEY before binding beyond loopback")
    uvicorn.run(create_app(settings), host=host, port=port, access_log=False)


if __name__ == "__main__":
    app()
