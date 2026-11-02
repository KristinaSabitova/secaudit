import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

log = logging.getLogger("notes")
mcp = FastMCP("notes")
ROOT = Path("/srv/notes").resolve()


@mcp.tool()
def note(name: str) -> str:
    """Read one note by name."""
    target = (ROOT / name).resolve()
    if ROOT not in target.parents:
        raise ValueError("outside the notes folder")
    log.info("note read: %s", name)
    return target.read_text()


if __name__ == "__main__":
    mcp.run()
