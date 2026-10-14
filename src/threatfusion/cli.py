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
    if result.mode == "demo":
        console.print(
            "[bold yellow]SIMULATED DEMO: fictional fixture values, not a real provider verdict.[/]"
        )
    risk_title = "Simulated risk" if result.mode == "demo" else "Risk"
    console.print(result.ioc.value, markup=False)
    console.print(
        f"{risk_title}: {s.risk if s.risk is not None else 'Unknown'} / 100 ({s.label}) | Confidence: {s.confidence}% | Coverage: {s.coverage}% | Freshness: {s.freshness}%"
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


@app.command("case-import")
def import_case_file(source: Path, title: str = "Imported investigation"):
    """Extract and prioritize a local text file without external queries."""
    from rich.text import Text

    from .extraction import extract_case
    from .triage import prioritize

    try:
        if source.stat().st_size > 800_000:
            raise ValueError("Text file too large; limit input to 200,000 characters")
        case = prioritize(
            extract_case(title, source.name[:120], source.read_text(encoding="utf-8-sig"))
        )
        Store(Settings().db_path).save_case(case)
    except (ValueError, OSError) as exc:
        console.print(str(exc), markup=False)
        raise typer.Exit(2) from exc
    console.print(f"Local case saved: {case.id}", markup=False)
    table = Table("Indicator", "Sightings", "Review priority", "Source lines")
    for item in case.indicators:
        table.add_row(
            Text(item.ioc.value),
            str(item.occurrences),
            item.priority,
            ", ".join(str(o.line) for o in item.observations),
        )
    console.print(table)
    console.print(
        "Import made no external lookups. Open the dashboard to review connections and record findings."
    )


@app.command("case-list")
def list_case_files(limit: int = typer.Option(20, min=1, max=100)):
    """List saved investigations."""
    for case in Store(Settings().db_path).cases(limit):
        console.print(f"{case.id} | {case.title} | {len(case.indicators)} indicators", markup=False)


@app.command("case-report")
def export_case_file(case_id: str, output: Path):
    """Export a saved case as JSON, CSV, or an investigation PDF brief."""
    from .case_reports import case_pdf, csv_report

    case = Store(Settings().db_path).get_case(case_id)
    if not case:
        raise typer.BadParameter("Case not found")
    format = output.suffix.lower()
    if format not in (".json", ".csv", ".pdf"):
        raise typer.BadParameter("Output must end in .json, .csv or .pdf")
    payload = (
        case_pdf(case)
        if format == ".pdf"
        else csv_report(case)
        if format == ".csv"
        else case.model_dump_json(indent=2).encode()
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    console.print(f"Case brief saved: {output}", markup=False)


if __name__ == "__main__":
    app()
