# Feedback Loop and Retraining System Integration Guide

## Overview

The feedback system enables analysts to correct pipeline verdicts, which are then used to automatically retrain and improve the phishing detection models. This creates a continuous learning loop.

## Architecture

### Components

1. **database.py** - SQLAlchemy async ORM layer
   - `DatabaseManager`: Async engine + session factory
   - Tables: FeedbackRecord, PipelineResult, LocalBlocklist, LocalAllowlist, RetrainRun

2. **retrainer.py** - Model retraining logic
   - `WeightRetainer`: Logistic regression on feedback feature vectors
   - `IntentClassifierRetrainer`: Intent category retraining (TF-IDF)
   - `RetrainOrchestrator`: Orchestrates full retraining pipeline + gap analysis

3. **scheduler.py** - Background automation
   - `RetrainScheduler`: Async scheduler that checks for retrain necessity every 24h
   - Supports manual triggers from API

4. **feedback_api.py** - FastAPI REST endpoints
   - POST `/api/v1/feedback` - Submit analyst corrections
   - GET `/api/v1/feedback/stats` - Precision/recall/F1 metrics
   - GET `/api/v1/feedback/export?format=csv|jsonl` - Export feedback
   - POST `/api/v1/retrain` - Manual retrain trigger
   - GET `/api/v1/retrain/history` - Retrain execution log
   - GET `/api/v1/retrain/gap-analysis` - Identify weak analyzers
   - GET `/api/v1/health` - Health check

## Quick Start

### 1. Initialize Database

```python
from src.feedback import DatabaseManager, create_sqlite_url
from src.config import PipelineConfig

config = PipelineConfig.from_env()
db_url = create_sqlite_url(config.feedback_db_path)

# Create database manager
db_manager = DatabaseManager(db_url)

# Initialize async (must be called before use)
await db_manager.initialize()

# Create tables
await db_manager.create_tables()
```

### 2. Start Scheduler

```python
from src.feedback import RetrainScheduler

scheduler = RetrainScheduler(config, db_manager, check_interval_hours=24)
await scheduler.start()

# ... do work ...

# Stop gracefully
await scheduler.stop()
```

### 3. Create FastAPI App

```python
from fastapi import FastAPI
from src.feedback import create_app

app = create_app(config, db_manager, scheduler)

# Run with: uvicorn main:app --reload
```

### 4. Set Bearer Token

```bash
export ANALYST_API_TOKEN="your-secret-token-here"
```

## API Usage Examples

### Submit Feedback

```bash
curl -X POST http://localhost:8000/api/v1/feedback \
  -H "Authorization: Bearer your-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "email_id": "msg_abc123",
    "original_verdict": "SUSPICIOUS",
    "correct_label": "CONFIRMED_PHISHING",
    "analyst_notes": "BEC indicators in body that NLP missed",
    "feature_vector": {
      "header_risk_score": 0.2,
      "url_reputation_score": 0.9,
      "domain_age_score": 0.3,
      "url_detonation_score": 0.8,
      "brand_impersonation_score": 0.1,
      "attachment_risk_score": 0.0,
      "nlp_intent_score": 0.3,
      "sender_reputation_score": 0.2
    }
  }'
```

### Get Performance Stats

```bash
curl -H "Authorization: Bearer your-secret-token" \
  http://localhost:8000/api/v1/feedback/stats
```

Response:
```json
{
  "total_feedback_records": 156,
  "total_unique_emails": 142,
  "false_positives": 24,
  "false_negatives": 8,
  "correct_verdicts": 124,
  "precision": 0.84,
  "recall": 0.94,
  "f1_score": 0.89,
  "last_updated": "2026-03-08T15:30:00Z"
}
```

### Export Feedback Records

```bash
# CSV format
curl -H "Authorization: Bearer your-secret-token" \
  "http://localhost:8000/api/v1/feedback/export?format=csv" \
  > feedback.csv

# JSONL format
curl -H "Authorization: Bearer your-secret-token" \
  "http://localhost:8000/api/v1/feedback/export?format=jsonl" \
  > feedback.jsonl
```

### Trigger Manual Retraining

```bash
curl -X POST \
  -H "Authorization: Bearer your-secret-token" \
  http://localhost:8000/api/v1/retrain
```

Response:
```json
{
  "run_id": "retrain_abc12345_1234567890",
  "status": "completed",
  "feedback_count": 87,
  "weights_updated": true,
  "new_weights": {
    "header_analysis": 0.12,
    "url_reputation": 0.16,
    "domain_intelligence": 0.08,
    "url_detonation": 0.18,
    "brand_impersonation": 0.09,
    "attachment_analysis": 0.14,
    "nlp_intent": 0.17,
    "sender_profiling": 0.06
  },
  "message": "Retraining completed successfully"
}
```

### View Retrain History

```bash
curl -H "Authorization: Bearer your-secret-token" \
  http://localhost:8000/api/v1/retrain/history?limit=10
```

### Gap Analysis (Weak Analyzers)

```bash
curl -H "Authorization: Bearer your-secret-token" \
  http://localhost:8000/api/v1/retrain/gap-analysis
```

Response (sorted by error count):
```json
[
  {
    "analyzer": "url_reputation",
    "false_negatives": 12,
    "false_positives": 3,
    "total_errors": 15,
    "fn_percentage": 80.0,
    "fp_percentage": 20.0,
    "high_confidence_errors": 8
  },
  {
    "analyzer": "nlp_intent",
    "false_negatives": 8,
    "false_positives": 7,
    "total_errors": 15,
    "fn_percentage": 53.3,
    "fp_percentage": 46.7,
    "high_confidence_errors": 4
  }
]
```

### Health Check

```bash
curl http://localhost:8000/api/v1/health
```

## Database Schema

### feedback_records
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| email_id | VARCHAR(255) | Email identifier |
| original_verdict | VARCHAR(50) | Pipeline's original classification |
| correct_label | VARCHAR(50) | Analyst's correction |
| analyst_notes | TEXT | Why analyst disagreed |
| feature_vector | TEXT | JSON dict of features (for retraining) |
| submitted_at | DATETIME | Submission timestamp |

Indexes: `email_id`, `original_verdict`, `submitted_at`

### pipeline_results
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| email_id | VARCHAR(255) | Email identifier (unique) |
| result_json | TEXT | Full PipelineResult as JSON |
| analyzed_at | DATETIME | Analysis timestamp |

### local_blocklist
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| indicator | VARCHAR(512) | Email, domain, URL, IP, hash, etc. |
| indicator_type | VARCHAR(50) | Type: email, domain, url, ip, hash |
| added_by | VARCHAR(100) | Analyst username or "system" |
| added_at | DATETIME | When added |
| reason | TEXT | Justification for blocklist |

Indexes: `indicator`, `indicator_type`, `added_at`

### local_allowlist
Similar to blocklist, for whitelisted senders/domains.

### retrain_runs
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| run_id | VARCHAR(100) | Unique identifier for this run |
| triggered_by | VARCHAR(100) | "scheduled" or username |
| feedback_records_used | INTEGER | Count in training set |
| model_improvement | VARCHAR(50) | e.g., "+2.3%" |
| started_at | DATETIME | Start time |
| completed_at | DATETIME | End time (NULL if pending) |
| status | VARCHAR(50) | pending, in_progress, completed, failed |
| error_message | TEXT | Error details if failed |

## Retraining Logic

### When to Retrain

Automatic retraining triggers when **any** of these conditions are met:

1. **≥20 new feedback records** since last successful retrain
2. **≥7 days** since last retrain (even if <20 new records)
3. **First retrain** with ≥50 total feedback records in database

### False Negative Handling

When analyst corrects a **false negative** (missed phishing → added to blocklist):
- Extract sender domain from email_id
- Add domain to `local_blocklist` with type="domain"
- Future emails from this domain get additional scrutiny

### False Positive Handling

When analyst corrects a **false positive** (legitimate → added to allowlist):
- Extract sender domain from email_id
- Add domain to `local_allowlist` with type="domain"
- Future emails from this domain bypass aggressive checks

### Weight Retraining

Logistic regression is trained on feedback feature vectors:

```
X: [header_risk, url_rep, domain_age, url_det, brand_imp, attach, nlp, sender]
y: Binary label (0=too conservative, 1=too aggressive)
```

Output: New weights that sum to 1.0, replacing original fixed weights.

### Gap Analysis

For each analyzer, tracks:
- Count of false negatives (missed phishing)
- Count of false positives (flagged legitimate)
- High-confidence errors (when score >0.7 but wrong)

Helps identify which analyzers need improvement.

## Logging

All modules use Python's standard `logging` module with `"src.feedback"` logger:

```python
import logging
logger = logging.getLogger(__name__)

# Set level
logging.getLogger("src.feedback").setLevel(logging.INFO)
```

Key log messages:
- `Database initialized`
- `Weight retraining complete`
- `Scheduled retrain completed`
- `Manual retrain triggered`
- `Gap analysis complete`

## Error Handling

All endpoints return appropriate HTTP status codes:
- `200 OK` - Success
- `201 Created` - Feedback accepted
- `400 Bad Request` - Invalid verdict values
- `401 Unauthorized` - Missing/invalid token
- `429 Too Many Requests` - Rate limit exceeded (60 req/min)
- `500 Internal Server Error` - Database/processing errors

## Configuration

### From Environment Variables

```bash
# Required
export ANALYST_API_TOKEN="secret-token"

# Optional (defaults shown)
export FEEDBACK_DB_PATH="data/feedback.db"
export LOG_LEVEL="INFO"
```

### Programmatically

```python
from src.config import PipelineConfig

config = PipelineConfig(
    feedback_db_path="data/feedback.db",
    analyst_api_token="secret-token",
)
```

## Testing

### Minimal Working Example

```python
import asyncio
from src.config import PipelineConfig
from src.feedback import DatabaseManager, create_app, RetrainScheduler, create_sqlite_url

async def main():
    # Setup
    config = PipelineConfig(analyst_api_token="test-token")
    db_url = create_sqlite_url("test_feedback.db")
    db_manager = DatabaseManager(db_url)

    await db_manager.initialize()
    await db_manager.create_tables()

    # Start scheduler
    scheduler = RetrainScheduler(config, db_manager)
    await scheduler.start()

    # Create API app
    app = create_app(config, db_manager, scheduler)

    # Use app with TestClient
    from fastapi.testclient import TestClient
    client = TestClient(app)

    # Health check
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200

    # Cleanup
    await scheduler.stop()
    await db_manager.close()

asyncio.run(main())
```

## Performance Notes

- **Async I/O**: All database operations are async for non-blocking behavior
- **SQLite**: Good for development; consider PostgreSQL for production (just change db_url)
- **Logistic Regression**: Trains on <1000 samples typically in <100ms
- **Rate Limiting**: In-memory counter; use Redis in production for distributed systems
- **Export**: Streams to client; memory-efficient for large datasets

## Future Enhancements

1. **A/B Testing**: Compare new vs old weights on holdout test set
2. **Intent Classifier**: Full TF-IDF + sklearn pipeline implementation
3. **Distributed Retraining**: Multi-process support for larger models
4. **Custom Metrics**: Add precision/recall per analyzer
5. **Redis Rate Limiting**: For multi-instance deployments
6. **Webhook Notifications**: Alert on significant improvements
7. **Model Versioning**: Track historical weights snapshots
8. **Feedback Validation**: Auto-flag contradictory feedback patterns

## Troubleshooting

### Database Locked
**Error**: `database is locked`
**Solution**: Ensure only one async session per operation. Use context managers properly.

### Feature Vector Mismatch
**Error**: `Failed to extract feature array`
**Solution**: Verify feature_vector JSON has all 8 keys (header_risk_score, etc.)

### Token Rejection
**Error**: `Invalid token`
**Solution**: Verify ANALYST_API_TOKEN environment variable matches header value exactly.

### Rate Limit Exceeded
**Error**: `429 Too Many Requests`
**Solution**: Wait 60 seconds, or request token cap increase from admin.

## Security Considerations

1. **Bearer Token**: Use strong random token (32+ chars). Rotate periodically.
2. **Database**: SQLite suitable for dev; use PostgreSQL with SSL in production.
3. **Input Validation**: Pydantic models validate all incoming data.
4. **SQL Injection**: SQLAlchemy ORM prevents injection via parameterized queries.
5. **CORS**: Add CORS middleware in production for frontend requests.

## See Also

- `src/models.py` - Data model definitions (Verdict, FeedbackRecord, etc.)
- `src/config.py` - Configuration loading from environment
- `src/feedback/README.md` - Module documentation (if present)
