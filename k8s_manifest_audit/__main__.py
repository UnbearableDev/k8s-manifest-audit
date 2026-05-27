"""Main entry point for the k8s-manifest-audit MCP Server Actor."""

import asyncio

from .main import main

if __name__ == "__main__":
    asyncio.run(main())
