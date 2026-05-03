# Feedback Loop and Retraining System

**Production-quality feedback collection and automated model retraining for the phishing detection pipeline.**

## Overview

This system creates a continuous learning loop where security analysts correct pipeline verdicts, which are automatically used to retrain and improve detection models.

### Key Features

- **Analyst Feedback API**: REST endpoints for submitting corrections with Bearer token auth
- **Automated Retraining**: Logistic regression on feedback feature vectors, scheduled every 24h
- **Performance Monitoring**: Real-time precision/recall/F1 metrics from corrections
- **Gap Analysis**: Identify which analyzers have the most errors
- **Local Blocklist/Allowlist**: Auto-populate from false negatives/positives
- **Async Database**: SQLAlchemy async ORM for non-blocking I/O
- **Rate Limiting**: 60 requests/minute per token
- **Export Support**: CSV and JSONL formats for external analysis
- **Full Type Hints**: Complete type annotations throughout
- **Comprehensive Logging**: Structured logging at all levels

## Modules

### 1. `database.py` - Data Persistence Layer

SQLAlchemy async ORM setup with five main tables:

**Tables:**
- `feedback_records` - Analyst corrections (email_id, original_verdict, correct_label, analyst_notes, feature_vector, submitted_at)
- `pipeline_results` - Snapshot of analysis results (email_id, result_json, analyzed_at)
- `local_blocklist` - Indicators from false negatives (indicator, indicator_type, added_by, added_at)
- `local_allowlist` - Indicators from false positives (indicator, indicator_type, added_by, added_at)
- `retrain_runs` - Audit log of retraining events (run_id, triggered_by, status, feedback_records_used, etc.)

**Classes:**
- `DatabaseManager` - Async session factory, table creation, engine management
- Tables mapped to SQLAlchemy ORM models with proper indexing

**Usage:**
```python
from src.feedback import DatabaseManager, create_sqlite_url

db_url = create_sqlite_url("data/feedback.db")
db_manager = DatabaseManager(db_url)
await db_manager.initialize()
await db_manager.create_tables()
```

### 2. `retrainer.py` - Model Retraining

**Classes:**

#### `WeightRetainer`
Retrains analyzer weights using logistic regression:
- Extracts feature vectors from feedback records
- Trains on mispredictions (where original_verdict != correct_label)
- Outputs new weights that sum to 1.0
- Includes StandardScaler for feature normalization

#### `IntentClassifierRetrainer`
Placeholder for TF-IDF + classifier retraining on intent mismatches.

#### `RetrainOrchestrator`
Main retraining orchestration:
- `should_retrain()` - Checks if retraining threshold met (≥20 new, ≥50 total, or ≥7 days)
- `run_full_retrain()` - Executes weights + intent retraining, logs results
- `get_gap_analysis()` - Identifies systematic weaknesses per analyzer

**Gap Analysis Output:**
```json
{
  "url_reputation": {
    "false_negatives": 12,
    "false_positives": 3,
    "total_errors": 15,
    "fn_percentage": 80.0,
    "fp_percentage": 20.0,
    "high_confidence_errors": 8
  }
}
```

### 3. `scheduler.py` - Background Automation

**Class:** `RetrainScheduler`

Async background scheduler:
- Checks `should_retrain()` every 24 hours (configurable)
- Automatically triggers `run_full_retrain()` when thresholds met
- Supports manual triggers via API
- Graceful start/stop with asyncio tasks
- Provides history and status endpoints

**Usage:**
```python
scheduler = RetrainScheduler(config, db_manager, check_interval_hours=24)
await scheduler.start()
# ... do work ...
await scheduler.stop()
```

### 4. `feedback_api.py` - FastAPI REST Layer

Complete REST API with Bearer token authentication and rate limiting.

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check (database, scheduler status) |
| POST | `/api/v1/feedback` | Submit analyst correction |
| GET | `/api/v1/feedback/stats` | Precision/recall/F1 metrics |
| GET | `/api/v1/feedback/export?format=csv\|jsonl` | Export feedback records |
| POST | `/api/v1/retrain` | Manually trigger retraining |
| GET | `/api/v1/retrain/history` | List past retrain runs |
| GET | `/api/v1/retrain/gap-analysis` | Identify weak analyzers |

**Request/Response Models** (Pydantic):
- `FeedbackSubmissionRequest` - Input validation for feedback
- `FeedbackResponse` - Feedback creation response
- `StatsResponse` - Metrics response
- `RetrainResponse` - Retrain trigger response
- `HealthResponse` - Health status
- `GapAnalysisResponse` - Gap analysis results

**Features:**
- Bearer token auth from config (`ANALYST_API_TOKEN`)
- Rate limiting: 60 req/min per token
- False negative → add to blocklist
- False positive → add to allowlist
- Streaming CSV/JSONL export
- Full error handling with appropriate HTTP status codes

## File Structure

```
src/feedback/
├── __init__.py                    # Module exports
├── database.py                    # SQLAlchemy ORM setup (268 lines)
├── retrainer.py                   # Weight/intent retraining logic (593 lines)
├── scheduler.py                   # Background scheduler (240 lines)
├── feedback_api.py                # FastAPI REST endpoints (793 lines)
├── main_example.py                # Example application setup (223 lines)
├── README.md                      # This file
└── INTEGRATION_GUIDE.md           # Detailed integration guide
```

**Total:** ~2,100 lines of production-quality Python code

## Quick Start

### 1. Install Dependencies

```bash
pip install sqlalchemy aiosqlite fastapi pydantic scikit-learn uvicorn
```

### 2. Set Environment Variable

```bash
export ANALYST_API_TOKEN="your-secret-token"
```

### 3. Run Example Server

```python
python -m src.feedback.main_example
# Server starts on http://localhost:8000
```

### 4. Submit Feedback

```bash
curl -X POST http://localhost:8000/api/v1/feedback \
  -H "Authorization: Bearer your-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "email_id": "msg_123",
    "original_verdict": "SUSPICIOUS",
    "correct_label": "CONFIRMED_PHISHING",
    "analyst_notes": "BEC patterns in body",
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

## Data Models

### FeedbackRecord

```python
@dataclass
class FeedbackRecord:
    email_id: str
    original_verdict: Verdict  # CLEAN, SUSPICIOUS, LIKELY_PHISHING, CONFIRMED_PHISHING
    correct_label: Verdict
    analyst_notes: str
    feature_vector: dict  # JSON of 8 analyzer scores
    submitted_at: datetime
```

### PipelineResult

```python
@dataclass
class PipelineResult:
    email_id: str
    result_json: str  # Full analysis as JSON
    analyzed_at: datetime
```

### LocalBlocklist / LocalAllowlist

```python
@dataclass
class LocalBlocklist:
    indicator: str  # Email, domain, URL, IP, hash
    indicator_type: str  # "email", "domain", "url", "ip", "hash"
    added_by: str  # Analyst name or "system"
    added_at: datetime
    reason: str  # Optional justification
```

### RetrainRun

```python
@dataclass
class RetrainRun:
    run_id: str
    triggered_by: str  # "scheduled" or username
    status: str  # "pending", "in_progress", "completed", "failed"
    feedback_records_used: int
    model_improvement: str  # e.g., "+2.3%"
    started_at: datetime
    completed_at: datetime
    error_message: str  # If failed
```

## Retraining Algorithm

### Weight Retraining

1. **Data Preparation:**
   - Extract feedback records where `original_verdict != correct_label`
   - Parse feature_vector JSON to get 8 analyzer scores
   - Label each as "too conservative" (0) or "too aggressive" (1)

2. **Training:**
   - Standardize features with StandardScaler
   - Train LogisticRegression with balanced class weights
   - Cross-validation to prevent overfitting

3. **Output:**
   - Extract coefficients and normalize to sum=1.0
   - Replace original fixed weights with new learned weights

### Retrain Triggers

Automatic retraining when ANY of these conditions met:

1. **≥20 new feedback records** since last successful retrain
2. **≥7 days** since last retrain (regardless of feedback count)
3. **First retrain** with ≥50 total feedback records

## API Examples

### Health Check

```bash
curl http://localhost:8000/api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2026-03-08T15:30:00Z",
  "database_connected": true,
  "scheduler_running": true
}
```

### Get Statistics

```bash
curl -H "Authorization: Bearer token" \
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
  "precision": 0.8400,
  "recall": 0.9400,
  "f1_score": 0.8900,
  "last_updated": "2026-03-08T15:30:00Z"
}
```

### Trigger Retraining

```bash
curl -X POST \
  -H "Authorization: Bearer token" \
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

### Gap Analysis

```bash
curl -H "Authorization: Bearer token" \
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

## Configuration

### Environment Variables

```bash
# Required
export ANALYST_API_TOKEN="secret-token-32-chars-minimum"

# Optional (defaults shown)
export FEEDBACK_DB_PATH="data/feedback.db"
export LOG_LEVEL="INFO"
export DASHBOARD_PORT="8000"
export FEEDBACK_API_HOST="127.0.0.1"
```

Keep the feedback API on loopback unless it is behind HTTPS, bearer
authentication, and an access-controlled reverse proxy.

### Programmatic Configuration

```python
from src.config import PipelineConfig

config = PipelineConfig(
    feedback_db_path="data/feedback.db",
    analyst_api_token="secret-token",
    log_level="INFO",
)
```

## Performance Characteristics

| Operation | Typical Time |
|-----------|--------------|
| Feedback submission | <50ms |
| Retrain on 100 samples | <200ms |
| Gap analysis | <100ms |
| Stats calculation | <100ms |
| Export 1000 records | <500ms |

## Error Handling

All endpoints return appropriate HTTP status codes:

| Code | Meaning | Example |
|------|---------|---------|
| 200 | Success | GET endpoints |
| 201 | Created | Feedback accepted |
| 400 | Bad Request | Invalid verdict |
| 401 | Unauthorized | Missing/invalid token |
| 429 | Rate Limited | >60 req/min |
| 500 | Server Error | Database failure |

## Security

- **Bearer Token**: Configured via `ANALYST_API_TOKEN` env variable
- **Rate Limiting**: In-memory per-token counters (60 req/min)
- **Input Validation**: Pydantic models for all request data
- **SQL Injection**: Prevented via SQLAlchemy parameterized queries
- **CORS**: Add middleware in production for frontend access

## Logging

All modules use Python's standard logging:

```python
import logging
logger = logging.getLogger(__name__)
```

Set level:
```python
logging.getLogger("src.feedback").setLevel(logging.DEBUG)
```

Key log messages:
- `Database initialized`
- `Weight retraining complete`
- `Scheduled retrain triggered`
- `Gap analysis complete`
- `Feedback submitted for ...`

## Testing

Minimal test example:

```python
import asyncio
from src.feedback import DatabaseManager, create_app, create_sqlite_url
from src.config import PipelineConfig

async def test():
    config = PipelineConfig(analyst_api_token="test-token")
    db_url = create_sqlite_url(":memory:")  # In-memory DB for testing
    db_manager = DatabaseManager(db_url)

    await db_manager.initialize()
    await db_manager.create_tables()

    app = create_app(config, db_manager)

    from fastapi.testclient import TestClient
    client = TestClient(app)

    # Test health
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200

    # Test auth
    resp = client.post("/api/v1/feedback")
    assert resp.status_code == 401  # Missing token

    await db_manager.close()

asyncio.run(test())
```

## Production Deployment

### 1. Use PostgreSQL Instead of SQLite

```python
db_url = "postgresql+asyncpg://user:pass@host:5432/feedback_db"
```

### 2. Add Redis Rate Limiting

Replace in-memory counter with Redis for distributed systems.

### 3. Add CORS Middleware

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://dashboard.example.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 4. Use Gunicorn/Uvicorn

```bash
gunicorn -k uvicorn.workers.UvicornWorker \
  -w 4 \
  --bind 0.0.0.0:8000 \
  src.feedback.main_example:app
```

### 5. Enable HTTPS

Use reverse proxy (nginx, Caddy) with SSL certificates.

## Future Enhancements

- A/B testing framework for weight changes
- Webhook notifications on significant improvements
- Model versioning and rollback
- Custom metrics per analyzer
- Distributed retraining support
- Multi-instance scheduler coordination
- Advanced feedback validation rules

## See Also

- `INTEGRATION_GUIDE.md` - Detailed integration and API documentation
- `main_example.py` - Complete working example application
- `src/models.py` - Data model definitions
- `src/config.py` - Configuration system

## License

Part of the Automated Phishing Detection pipeline.

## Support

For issues or questions, refer to:
1. `INTEGRATION_GUIDE.md` for API details
2. Module docstrings for class/method documentation
3. `main_example.py` for usage patterns
