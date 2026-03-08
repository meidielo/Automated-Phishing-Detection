"""Automation services for continuous email monitoring."""
from src.automation.email_monitor import EmailMonitor, AlertDispatcher, ResultStore

__all__ = ["EmailMonitor", "AlertDispatcher", "ResultStore"]
