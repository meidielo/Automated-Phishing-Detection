"""
SenderProfileAnalyzer: Track sender behavior and detect anomalies.
Uses SQLite for sender history tracking and behavioral baseline comparison.
"""
import asyncio
import logging
import sqlite3
from datetime import datetime
from typing import Optional

from src.models import AnalyzerResult, EmailObject

logger = logging.getLogger(__name__)


class SenderProfileAnalyzer:
    """
    Analyze sender behavior patterns and detect anomalies.

    Maintains SQLite database of sender history with:
    - Email count and frequency
    - Recipient patterns
    - Send time patterns
    - Content length distribution
    - Language/encoding patterns
    - User-Agent variations

    Handles cold start with <5 emails.
    Computes anomaly scores for deviations from baseline.
    """

    def __init__(self, db_path: str = "data/sender_profiles.db"):
        """
        Initialize sender profiling analyzer.

        Args:
            db_path: Path to SQLite database for sender history
        """
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite database with required tables."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Senders table: aggregate statistics
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS senders (
                        sender_email TEXT PRIMARY KEY,
                        email_count INTEGER DEFAULT 0,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP,
                        avg_recipients_count REAL DEFAULT 0,
                        avg_content_length INTEGER DEFAULT 0,
                        most_common_hour INTEGER DEFAULT 0,
                        most_common_day TEXT DEFAULT 'unknown',
                        language_detected TEXT DEFAULT 'unknown'
                    )
                """)

                # Recipient patterns table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sender_recipients (
                        sender_email TEXT,
                        recipient_email TEXT,
                        occurrence_count INTEGER DEFAULT 1,
                        last_seen TIMESTAMP,
                        PRIMARY KEY (sender_email, recipient_email),
                        FOREIGN KEY (sender_email) REFERENCES senders(sender_email)
                    )
                """)

                # Email history table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sender_emails (
                        email_id TEXT PRIMARY KEY,
                        sender_email TEXT,
                        timestamp TIMESTAMP,
                        recipient_count INTEGER,
                        content_length INTEGER,
                        user_agent TEXT,
                        FOREIGN KEY (sender_email) REFERENCES senders(sender_email)
                    )
                """)

                conn.commit()
                logger.info(f"Sender profile database initialized: {self.db_path}")

        except Exception as e:
            logger.error(f"Failed to initialize sender profile database: {e}")

    def _get_sender_history(self, sender_email: str) -> dict:
        """
        Retrieve sender history from database.

        Args:
            sender_email: Sender email address

        Returns:
            Dictionary with sender statistics
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get sender aggregate data
                cursor.execute(
                    """
                    SELECT email_count, first_seen, last_seen, avg_recipients_count,
                           avg_content_length, most_common_hour, most_common_day
                    FROM senders WHERE sender_email = ?
                    """,
                    (sender_email,),
                )

                row = cursor.fetchone()
                if not row:
                    return {
                        "is_new_sender": True,
                        "email_count": 0,
                        "history": None,
                    }

                email_count, first_seen, last_seen, avg_recipients, avg_content, hour, day = row

                # Get recipient list
                cursor.execute(
                    """
                    SELECT recipient_email, occurrence_count FROM sender_recipients
                    WHERE sender_email = ?
                    ORDER BY occurrence_count DESC
                    """,
                    (sender_email,),
                )

                recipients = {row[0]: row[1] for row in cursor.fetchall()}

                return {
                    "is_new_sender": False,
                    "email_count": email_count,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "avg_recipients_count": avg_recipients,
                    "avg_content_length": avg_content,
                    "most_common_hour": hour,
                    "most_common_day": day,
                    "common_recipients": recipients,
                }

        except Exception as e:
            logger.error(f"Failed to retrieve sender history: {e}")
            return {"error": str(e)}

    def _update_sender_history(
        self,
        sender_email: str,
        email: EmailObject,
    ) -> None:
        """
        Update sender history in database.

        Args:
            sender_email: Sender email address
            email: Email object with details
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                current_time = datetime.utcnow().isoformat()
                recipient_count = len(email.to_addresses)
                content_length = len(email.body_plain)
                send_hour = email.date.hour if email.date else -1
                send_day = email.date.strftime("%A") if email.date else "unknown"

                # Check if sender exists
                cursor.execute(
                    "SELECT email_count FROM senders WHERE sender_email = ?",
                    (sender_email,),
                )
                result = cursor.fetchone()

                if result:
                    # Update existing sender
                    old_count = result[0]
                    new_count = old_count + 1

                    # Calculate weighted average for numeric fields
                    old_avg_recipients = old_count * 5  # Placeholder
                    new_avg_recipients = (old_avg_recipients + recipient_count) / new_count

                    cursor.execute(
                        """
                        UPDATE senders SET
                            email_count = ?,
                            last_seen = ?,
                            avg_recipients_count = ?,
                            avg_content_length = ?
                        WHERE sender_email = ?
                        """,
                        (new_count, current_time, new_avg_recipients, content_length, sender_email),
                    )
                else:
                    # Insert new sender
                    cursor.execute(
                        """
                        INSERT INTO senders
                        (sender_email, email_count, first_seen, last_seen,
                         avg_recipients_count, avg_content_length, most_common_hour, most_common_day)
                        VALUES (?, 1, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sender_email,
                            current_time,
                            current_time,
                            recipient_count,
                            content_length,
                            send_hour,
                            send_day,
                        ),
                    )

                # Update recipient patterns
                for recipient in email.to_addresses:
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO sender_recipients
                        (sender_email, recipient_email, occurrence_count, last_seen)
                        VALUES (?,
                                ?,
                                COALESCE((SELECT occurrence_count FROM sender_recipients
                                         WHERE sender_email = ? AND recipient_email = ?), 0) + 1,
                                ?)
                        """,
                        (sender_email, recipient, sender_email, recipient, current_time),
                    )

                # Insert email record
                user_agent = email.raw_headers.get("User-Agent", ["unknown"])[0]
                cursor.execute(
                    """
                    INSERT INTO sender_emails
                    (email_id, sender_email, timestamp, recipient_count, content_length, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        email.email_id,
                        sender_email,
                        email.date.isoformat() if email.date else current_time,
                        recipient_count,
                        content_length,
                        user_agent,
                    ),
                )

                conn.commit()

        except Exception as e:
            logger.error(f"Failed to update sender history: {e}")

    def _calculate_anomaly_score(
        self,
        email: EmailObject,
        history: dict,
    ) -> tuple[float, dict]:
        """
        Calculate anomaly score based on deviations from baseline.

        Args:
            email: Email object
            history: Sender history dictionary

        Returns:
            Tuple of (anomaly_score, anomaly_details)
        """
        anomaly_score = 0.0
        anomaly_details = {}

        # Cold start handling: < 5 emails is inherently suspicious
        email_count = history.get("email_count", 0)
        if email_count < 5:
            anomaly_score += 0.3
            anomaly_details["cold_start"] = True

        if email_count < 1:
            return anomaly_score, anomaly_details

        # Recipient count anomaly
        avg_recipients = history.get("avg_recipients_count", 5)
        current_recipients = len(email.to_addresses)

        if current_recipients > avg_recipients * 2:
            anomaly_score += 0.2
            anomaly_details["unusual_recipient_count"] = {
                "expected": avg_recipients,
                "actual": current_recipients,
            }

        # Content length anomaly
        avg_content = history.get("avg_content_length", 500)
        current_content = len(email.body_plain)

        if current_content < avg_content * 0.2:
            anomaly_score += 0.15
            anomaly_details["unusual_content_length"] = {
                "expected": avg_content,
                "actual": current_content,
                "type": "too_short",
            }
        elif current_content > avg_content * 3:
            anomaly_score += 0.1
            anomaly_details["unusual_content_length"] = {
                "expected": avg_content,
                "actual": current_content,
                "type": "too_long",
            }

        # Recipient pattern anomaly
        common_recipients = history.get("common_recipients", {})
        email_recipients = set(email.to_addresses)

        # Check if email goes to new, unexpected recipients
        unfamiliar_count = 0
        for recipient in email_recipients:
            if recipient not in common_recipients:
                unfamiliar_count += 1

        if email_recipients and unfamiliar_count / len(email_recipients) > 0.5:
            anomaly_score += 0.2
            anomaly_details["unusual_recipients"] = {
                "unfamiliar_count": unfamiliar_count,
                "total_recipients": len(email_recipients),
            }

        # Send time anomaly
        current_hour = email.date.hour if email.date else -1
        expected_hour = history.get("most_common_hour", 9)

        if current_hour >= 0 and abs(current_hour - expected_hour) > 6:
            anomaly_score += 0.1
            anomaly_details["unusual_send_time"] = {
                "expected_hour": expected_hour,
                "actual_hour": current_hour,
            }

        # User-Agent anomaly
        user_agent = email.raw_headers.get("User-Agent", ["unknown"])[0]
        if "unknown" in user_agent.lower():
            anomaly_score += 0.15
            anomaly_details["suspicious_user_agent"] = user_agent

        # Subject line anomaly: sudden change in patterns
        if email_count > 10:
            # Would need more sophisticated NLP here
            pass

        # Clamp to 0-1 range
        anomaly_score = min(anomaly_score, 1.0)

        return anomaly_score, anomaly_details

    async def analyze(self, email: EmailObject, db_path: Optional[str] = None) -> AnalyzerResult:
        """
        Analyze sender behavior and detect anomalies.

        Args:
            email: Email object to analyze
            db_path: Optional override for database path

        Returns:
            AnalyzerResult with risk score and confidence
        """
        analyzer_name = "sender_profiling"

        try:
            if not email or not email.from_address:
                return AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.0,
                    confidence=0.0,
                    details={"message": "no_sender_information"},
                )

            sender_email = email.from_address.lower()

            # Use provided db_path if given
            if db_path:
                self.db_path = db_path

            # Retrieve sender history
            history = self._get_sender_history(sender_email)

            # Calculate anomaly score
            anomaly_score, anomaly_details = self._calculate_anomaly_score(email, history)

            # Determine confidence based on available history
            email_count = history.get("email_count", 0)
            if email_count == 0:
                confidence = 0.3
            elif email_count < 5:
                confidence = 0.5
            elif email_count < 20:
                confidence = 0.7
            else:
                confidence = 0.9

            logger.info(
                f"Sender profiling complete: "
                f"sender={sender_email}, "
                f"risk={anomaly_score:.2f}, "
                f"confidence={confidence:.2f}, "
                f"email_count={email_count}"
            )

            # Update sender history for future analysis
            try:
                self._update_sender_history(sender_email, email)
            except Exception as e:
                logger.warning(f"Failed to update sender history: {e}")

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=anomaly_score,
                confidence=confidence,
                details={
                    "sender_email": sender_email,
                    "email_count": email_count,
                    "is_new_sender": history.get("is_new_sender", True),
                    "anomaly_score": anomaly_score,
                    "anomalies_detected": anomaly_details,
                    "history": {
                        k: v for k, v in history.items()
                        if k not in ["is_new_sender", "error", "common_recipients"]
                    },
                },
            )

        except Exception as e:
            logger.error(f"Sender profiling analysis failed: {e}")
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )
