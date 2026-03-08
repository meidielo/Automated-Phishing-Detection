"""
IMAP email fetcher for the phishing detection pipeline.

Polls a configured IMAP mailbox at a configurable interval,
fetches new emails, and feeds them into the analysis pipeline.
"""
import asyncio
import email
import imaplib
import logging
import ssl
import time
from datetime import datetime, timedelta
from typing import AsyncGenerator, Callable, Optional

from src.config import IMAPConfig
from src.extractors.eml_parser import EMLParser
from src.models import EmailObject

logger = logging.getLogger(__name__)


class IMAPFetcher:
    """
    Polls an IMAP mailbox for new emails and yields EmailObject instances.

    Supports:
    - Configurable poll interval
    - SSL/TLS connections
    - UID-based tracking to avoid re-processing
    - Folder selection
    - Graceful reconnection on failure
    - Callback-based or async generator usage
    """

    def __init__(
        self,
        config: IMAPConfig,
        parser: Optional[EMLParser] = None,
        on_email: Optional[Callable] = None,
    ):
        """
        Args:
            config: IMAP connection configuration
            parser: EMLParser instance (created if not provided)
            on_email: Optional callback invoked for each new EmailObject
        """
        self.config = config
        self.parser = parser or EMLParser()
        self.on_email = on_email
        self._connection: Optional[imaplib.IMAP4_SSL] = None
        self._last_uid: Optional[str] = None
        self._running = False
        self._processed_uids: set[str] = set()
        self._uid_by_email_id: dict[str, str] = {}  # email_id → imap uid
        self._reconnect_delay = 5  # seconds
        self._max_reconnect_delay = 300  # 5 minutes

    def connect(self) -> imaplib.IMAP4_SSL:
        """
        Establish IMAP connection with SSL.

        Returns:
            Connected IMAP4_SSL instance

        Raises:
            imaplib.IMAP4.error: On connection/auth failure
        """
        logger.info(f"Connecting to IMAP server {self.config.host}:{self.config.port}")

        ctx = ssl.create_default_context()
        conn = imaplib.IMAP4_SSL(
            host=self.config.host,
            port=self.config.port,
            ssl_context=ctx,
        )

        conn.login(self.config.user, self.config.password)
        logger.info(f"Authenticated as {self.config.user}")

        status, _ = conn.select(self.config.folder, readonly=False)
        if status != "OK":
            raise imaplib.IMAP4.error(f"Failed to select folder: {self.config.folder}")

        logger.info(f"Selected folder: {self.config.folder}")
        self._connection = conn
        return conn

    def disconnect(self):
        """Close the IMAP connection gracefully."""
        if self._connection:
            try:
                self._connection.close()
                self._connection.logout()
            except Exception as e:
                logger.debug(f"Disconnect cleanup error (non-fatal): {e}")
            finally:
                self._connection = None

    def _ensure_connected(self) -> imaplib.IMAP4_SSL:
        """Reconnect if connection is lost."""
        if self._connection is None:
            self.connect()
        try:
            self._connection.noop()
        except Exception:
            logger.warning("IMAP connection lost, reconnecting...")
            self._connection = None
            self.connect()
        return self._connection

    def fetch_new_uids(self, since: Optional[datetime] = None) -> list[str]:
        """
        Fetch UIDs of unseen/new emails.

        Args:
            since: Only fetch emails since this date (default: last 24h)

        Returns:
            List of UID strings
        """
        conn = self._ensure_connected()

        if since is None:
            since = datetime.utcnow() - timedelta(days=1)

        date_str = since.strftime("%d-%b-%Y")
        search_criteria = f'(SINCE {date_str} UNSEEN)'

        status, data = conn.uid("search", None, search_criteria)
        if status != "OK":
            logger.error(f"IMAP search failed: {status}")
            return []

        uids = data[0].decode().split()
        # Filter out already-processed UIDs
        new_uids = [uid for uid in uids if uid not in self._processed_uids]

        logger.debug(f"Found {len(uids)} unseen emails, {len(new_uids)} new")
        return new_uids

    def fetch_email_by_uid(self, uid: str) -> Optional[EmailObject]:
        """
        Fetch a single email by UID and parse it.

        Args:
            uid: IMAP UID string

        Returns:
            Parsed EmailObject or None on failure
        """
        conn = self._ensure_connected()

        status, data = conn.uid("fetch", uid, "(RFC822)")
        if status != "OK" or not data or data[0] is None:
            logger.error(f"Failed to fetch UID {uid}: {status}")
            return None

        raw_email = data[0][1]
        if isinstance(raw_email, bytes):
            raw_email_str = raw_email.decode("utf-8", errors="replace")
        else:
            raw_email_str = raw_email

        try:
            email_obj = self.parser.parse_bytes(raw_email_str)
            self._processed_uids.add(uid)
            self._uid_by_email_id[email_obj.email_id] = uid
            logger.info(
                f"Parsed email UID={uid}: subject='{email_obj.subject}', "
                f"from='{email_obj.from_address}'"
            )
            return email_obj
        except Exception as e:
            logger.error(f"Failed to parse email UID={uid}: {e}")
            return None

    def fetch_all_new(self, since: Optional[datetime] = None) -> list[EmailObject]:
        """
        Fetch and parse all new emails since the given date.

        Args:
            since: Only fetch emails since this date

        Returns:
            List of parsed EmailObject instances
        """
        uids = self.fetch_new_uids(since=since)
        emails = []

        for uid in uids:
            email_obj = self.fetch_email_by_uid(uid)
            if email_obj is not None:
                emails.append(email_obj)

        logger.info(f"Fetched {len(emails)} new emails from {self.config.folder}")
        return emails

    def get_uid_for_email(self, email_id: str) -> Optional[str]:
        """Look up the IMAP UID for a parsed email by its email_id."""
        return self._uid_by_email_id.get(email_id)

    def move_to_folder(self, uid: str, destination: str) -> bool:
        """
        Move an email by UID to a destination folder.

        Uses IMAP MOVE extension if available, otherwise falls back to
        COPY + mark deleted + expunge.

        Args:
            uid: IMAP UID of the email to move
            destination: Destination mailbox name (e.g. "Quarantine")

        Returns:
            True on success, False on failure
        """
        try:
            conn = self._ensure_connected()

            # Try RFC 6851 MOVE command first (Gmail, Dovecot, Exchange support it)
            status, _ = conn.uid("move", uid, destination)
            if status == "OK":
                logger.info(f"Moved UID {uid} to '{destination}' via MOVE")
                return True

            # Fallback: COPY + mark \Deleted + expunge
            status, _ = conn.uid("copy", uid, destination)
            if status != "OK":
                logger.error(f"COPY UID {uid} to '{destination}' failed: {status}")
                return False

            conn.uid("store", uid, "+FLAGS", "\\Deleted")
            conn.expunge()
            logger.info(f"Moved UID {uid} to '{destination}' via COPY+DELETE")
            return True

        except Exception as e:
            logger.error(f"Failed to move UID {uid} to '{destination}': {e}")
            return False

    def ensure_folder_exists(self, folder: str) -> bool:
        """Create folder if it doesn't already exist."""
        try:
            conn = self._ensure_connected()
            status, _ = conn.create(folder)
            if status == "OK":
                logger.info(f"Created IMAP folder: {folder}")
            return True
        except Exception as e:
            # Folder likely already exists
            logger.debug(f"ensure_folder_exists({folder}): {e}")
            return True

    async def poll_loop(
        self,
        interval: Optional[int] = None,
        max_iterations: Optional[int] = None,
    ):
        """
        Continuously poll for new emails at the configured interval.

        Args:
            interval: Override poll interval in seconds (default from config)
            max_iterations: Stop after N polls (None = run forever)
        """
        poll_interval = interval or self.config.poll_interval_seconds
        self._running = True
        iteration = 0
        reconnect_delay = self._reconnect_delay

        logger.info(
            f"Starting IMAP poll loop: server={self.config.host}, "
            f"folder={self.config.folder}, interval={poll_interval}s"
        )

        while self._running:
            if max_iterations is not None and iteration >= max_iterations:
                logger.info(f"Reached max iterations ({max_iterations}), stopping")
                break

            try:
                emails = self.fetch_all_new()
                reconnect_delay = self._reconnect_delay  # reset on success

                for email_obj in emails:
                    if self.on_email:
                        try:
                            result = self.on_email(email_obj)
                            if asyncio.iscoroutine(result):
                                await result
                        except Exception as e:
                            logger.error(
                                f"Callback error for email {email_obj.email_id}: {e}"
                            )

                iteration += 1

            except imaplib.IMAP4.abort:
                logger.warning("IMAP connection aborted, will reconnect")
                self._connection = None

            except Exception as e:
                logger.error(f"Poll iteration error: {e}")
                reconnect_delay = min(reconnect_delay * 2, self._max_reconnect_delay)
                logger.info(f"Waiting {reconnect_delay}s before retry")

            await asyncio.sleep(poll_interval)

        self.disconnect()
        logger.info("IMAP poll loop stopped")

    def stop(self):
        """Signal the poll loop to stop."""
        self._running = False

    async def stream(
        self,
        since: Optional[datetime] = None,
        interval: Optional[int] = None,
    ) -> AsyncGenerator[EmailObject, None]:
        """
        Async generator that yields new emails as they arrive.

        Usage:
            async for email_obj in fetcher.stream():
                result = await pipeline.analyze(email_obj)

        Args:
            since: Initial lookback period
            interval: Poll interval in seconds
        """
        poll_interval = interval or self.config.poll_interval_seconds
        self._running = True

        while self._running:
            try:
                emails = self.fetch_all_new(since=since)
                for email_obj in emails:
                    yield email_obj
                # After first poll, only get truly new emails
                since = datetime.utcnow() - timedelta(seconds=poll_interval + 10)
            except Exception as e:
                logger.error(f"Stream error: {e}")

            await asyncio.sleep(poll_interval)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
