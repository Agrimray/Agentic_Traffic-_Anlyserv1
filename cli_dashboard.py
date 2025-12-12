# cli_dashboard.py
import asyncio
import datetime

async def dashboard_print(message: str):
    """
    Asynchronous dashboard printer.
    Ensures logs appear cleanly without blocking main event loop.
    """
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[DASHBOARD {ts}] {message}")
