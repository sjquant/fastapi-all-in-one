from typing import Annotated, Any

import typer
import uvicorn

from alembic.config import Config
from app.core.config import config

app = typer.Typer()


@app.command(help="Show current revision.")
def currentrevision():
    """
    Show current revision.

    This function shows the current revision of the database using Alembic.
    """
    from alembic.command import current

    alembic_ini_path = "./alembic.ini"
    alembic_cfg = Config(alembic_ini_path)
    alembic_cfg.set_main_option("sqlalchemy.url", db_url())

    current(alembic_cfg)


@app.command(help="Prints the migration history using Alembic.")
def migrationshistory():
    """
    Prints the migration history using Alembic.

    Returns:
        None
    """
    from alembic.command import history

    alembic_ini_path = "./alembic.ini"
    alembic_cfg = Config(alembic_ini_path)

    history(alembic_cfg)


@app.command(help="Create a new Alembic migration.")
def makemigrations(m: Annotated[str, typer.Option(help="The migration message.")] = ""):
    """
    Create a new Alembic migration.

    Args:
        m: The migration message.

    Returns:
        None
    """
    from alembic.command import revision

    alembic_ini_path = "./alembic.ini"
    alembic_cfg = Config(alembic_ini_path)
    alembic_cfg.set_main_option("sqlalchemy.url", db_url())

    revision_kwargs: dict[str, Any] = {"autogenerate": True}
    revision_kwargs["message"] = m
    revision(alembic_cfg, **revision_kwargs)


@app.command(help="Upgrade the database schema to the latest version.")
def migrate(
    revision: Annotated[
        str, typer.Option(help="The revision to upgrade to. Defaults to 'head'.")
    ] = "head"
):
    """
    Upgrade the database schema to the latest version.

    Args:
        revision: The revision to upgrade to. Defaults to "head".
    """
    from alembic.command import upgrade

    alembic_ini_path = "./alembic.ini"
    alembic_cfg = Config(alembic_ini_path)
    alembic_cfg.set_main_option("sqlalchemy.url", db_url())

    upgrade(alembic_cfg, revision)


@app.command(help="Downgrade the database schema by a specified number of revisions.")
def downgrade(
    step: Annotated[
        int, typer.Option(help="The number of revisions to downgrade. Defaults to 1.")
    ] = 1
):
    """
    Downgrade the database schema by a specified number of revisions.

    Args:
        step: The number of revisions to downgrade. Defaults to 1.

    Returns:
        None
    """
    from alembic.command import downgrade

    alembic_ini_path = "./alembic.ini"
    alembic_cfg = Config(alembic_ini_path)
    alembic_cfg.set_main_option("sqlalchemy.url", db_url())

    downgrade(alembic_cfg, f"-{step}")


@app.command(help="Stamp the revision of the database schema.")
def stamp(revision: Annotated[str, typer.Option(help="The revision number to stamp.")]):
    """
    Stamp the revision of the database schema.

    Args:
        revision: The revision number to stamp.

    Returns:
        None
    """
    from alembic.command import stamp

    alembic_ini_path = "./alembic.ini"
    alembic_cfg = Config(alembic_ini_path)
    alembic_cfg.set_main_option("sqlalchemy.url", db_url())

    stamp(alembic_cfg, revision)


@app.command(help="Runs the server.")
def runserver(
    host: Annotated[
        str, typer.Option(help="The host to bind the server to. Defaults to '0.0.0.0'.")
    ] = "0.0.0.0",
    port: Annotated[
        int, typer.Option(help="The port to bind the server to. Defaults to 8000.")
    ] = 8000,
):
    """
    Runs the server

    Args:
        host: The host to bind the server to. Defaults to "0.0.0.0".
        port: The port to bind the server to. Defaults to 8000.
    """
    uvicorn.run("app.main:app", host=host, port=port, reload=True)  # pyright: ignore


def db_url():
    return str(config.db_url).replace("+asyncpg", "")


if __name__ == "__main__":
    app()
