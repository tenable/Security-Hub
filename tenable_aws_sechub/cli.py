"""
Simple CLI wrapper for commandline interaction with the integration.
"""

import logging
from pathlib import Path
from typing_extensions import Annotated
import typer
import tomlkit
from rich.logging import RichHandler
from .transform import Processor


app = typer.Typer(add_completion=False)


@app.command()
def sechub(
    configfile: Path = Path('tvm2aws.toml'),
    verbose: Annotated[int, typer.Option('--verbose', '-v', max=5, count=True)] = 2,
):
    """
    Tenable to AWS Security Hub vulnerability finding importer.
    """
    # Set the logging handler.
    logging.basicConfig(
        level=(5 - verbose) * 10,
        datefmt='[%X]',
        handlers=[RichHandler(rich_tracebacks=True)],
    )

    # Read the configuration file
    with configfile.open('r', encoding='utf-8') as cobj:
        config = tomlkit.load(cobj)

    # Instantiate and run the ingestion processor.
    processor = Processor(config)
    processor.ingest()

    # Write out the updated configuration file with the updated parameters.
    with configfile.open('w', encoding='utf-8') as cobj:
        tomlkit.dump(processor.config, cobj)
