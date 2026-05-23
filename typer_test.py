import typer
from typing import Annotated, Optional

app = typer.Typer()

@app.command(context_settings={"ignore_unknown_options": True})
def scan(
    ctx: typer.Context,
    path: str = ".",
    ignore: Annotated[
        Optional[list[str]],
        typer.Option("--ignore", "-i", help="Ignore dirs")
    ] = None
):
    print("path:", path)
    
    final_ignores = list(ignore) if ignore else []
    # If there are unknown args, maybe they belong to ignore?
    # This is tricky because we don't know if they came after --ignore
    
    print("ignore:", ignore)
    print("ctx.args:", ctx.args)

if __name__ == "__main__":
    app()
