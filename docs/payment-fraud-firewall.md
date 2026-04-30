# Payment Fraud Firewall

This product layer turns the phishing detector into a payment decision guard for SMEs.

Instead of only answering "is this email phishing?", it also answers:

- `SAFE`: no material payment scam indicators were found.
- `VERIFY`: do not pay until the supplier or executive is verified independently.
- `DO_NOT_PAY`: block payment release until verification is completed.

## What It Detects

- Fake invoice emails
- Supplier impersonation
- Changed bank detail requests
- Urgent payment pressure
- Approval bypass or secrecy language
- CEO/CFO style transfer requests
- Reply-to domain mismatch
- SPF, DKIM, or DMARC failure on payment requests
- Free-email supplier payment requests
- Risky invoice-themed attachments
- Bank details, BSBs, account numbers, IBANs, SWIFT/BIC codes, PayIDs, ABNs, and amounts

Sensitive payment identifiers are masked in analyzer output by default.

## Pipeline Integration

The new analyzer is `src/analyzers/payment_fraud.py`.

It runs as part of the existing analyzer set under the name `payment_fraud`, and returns:

- risk score
- confidence
- payment decision
- explainable signals
- masked payment fields
- verification steps

The pipeline uses the payment decision as a business-aware override:

- `DO_NOT_PAY` with high risk maps to `CONFIRMED_PHISHING`.
- `DO_NOT_PAY` with moderate risk maps to at least `LIKELY_PHISHING`.
- `VERIFY` maps a clean email to at least `SUSPICIOUS`.

## Recommended SME Workflow

When an email returns `VERIFY` or `DO_NOT_PAY`:

1. Do not use links, phone numbers, or reply-to addresses from the email.
2. Call the supplier or executive using a saved contact from the accounting system.
3. Compare bank details with the last approved supplier payment record.
4. Require second-person approval for any bank-detail change.
5. Record verifier name, date, and approval outcome before releasing funds.

## Payment Scam Dataset

Keep this dataset separate from the generic phishing corpora. Generic phishing
labels answer "is this malicious"; the payment dataset also answers "what
should the business do before paying".

Initialize it locally:

```bash
python scripts/payment_dataset.py init --dataset data/payment_scam_dataset
```

Redact raw payment emails before labeling:

```bash
python scripts/payment_dataset.py redact \
  --source path/to/raw-payment-email.eml \
  --output data/payment_scam_dataset/incoming/redacted/vendor-update.eml

python scripts/payment_dataset.py audit-pii \
  --sample data/payment_scam_dataset/incoming/redacted/vendor-update.eml
```

The redactor pseudonymizes email and URL domains, normalizes obvious payment
identifiers such as BSBs and account numbers, removes non-text attachments, and
reports possible leaks by fingerprint instead of echoing sensitive values. It is
a safety rail, not a privacy guarantee, so manually review every redacted sample
before adding it.

Add a labeled `.eml`:

```bash
python scripts/payment_dataset.py add \
  --dataset data/payment_scam_dataset \
  --source path/to/redacted-sample.eml \
  --label PAYMENT_SCAM \
  --payment-decision DO_NOT_PAY \
  --scenario bank_detail_change \
  --source-type redacted \
  --split train \
  --verified-by meidie \
  --contains-real-pii no \
  --notes "Supplier bank details changed with urgency and reply-to mismatch"
```

Validate and export generic eval labels:

```bash
python scripts/payment_dataset.py validate --dataset data/payment_scam_dataset
python scripts/payment_dataset.py export-eval-labels --dataset data/payment_scam_dataset
python scripts/payment_dataset.py export-ml-jsonl --dataset data/payment_scam_dataset
python scripts/payment_dataset.py readiness --dataset data/payment_scam_dataset
python scripts/payment_eval.py --dataset data/payment_scam_dataset
python scripts/payment_eval.py \
  --dataset data/payment_scam_dataset \
  --split holdout \
  --output-prefix data/payment_scam_dataset/reports/payment_holdout_eval
python scripts/payment_train.py --dataset data/payment_scam_dataset
python scripts/payment_demo.py --dataset data/payment_scam_dataset
```

`export-ml-jsonl` refuses samples that are not marked `contains_real_pii=no`
unless `--allow-pii` is explicitly passed. Keep the default refusal for normal
experiments.

`payment_eval.py` writes JSON, CSV, and Markdown reports under
`data/payment_scam_dataset/reports/` comparing expected vs predicted `SAFE`,
`VERIFY`, and `DO_NOT_PAY` decisions. Reports include accuracy by source type
and split, and `--split holdout` can be used for the public-derived holdout set.

`payment_train.py` trains and tests a TF-IDF + logistic regression baseline on
the exported ML JSONL. It writes ignored model artifacts and metrics under
`models/payment_classifier/`. Rows marked `split=holdout` are excluded from
training and reported separately. When the payment-decision model exists, the
payment analyzer includes an `ml_decision` sidecar so analysts can compare the
rules decision against the model prediction without letting synthetic-only ML
override payment release. Treat synthetic-only accuracy as a plumbing check, not
a production metric.

`payment_demo.py` prints one compact expected-vs-predicted table across `SAFE`,
`VERIFY`, and `DO_NOT_PAY`, preferring PII-free redacted/public rows over
synthetic rows.

`readiness` is the honesty check. It reports whether the dataset is still
synthetic-only and whether non-synthetic samples are PII-free, balanced across
payment decisions, and assigned to train, validation, and test splits.

Seed the first reproducible development set:

```bash
python scripts/payment_dataset.py seed-synthetic \
  --dataset data/payment_scam_dataset \
  --scam-count 50 \
  --legit-count 50 \
  --safe-count 50 \
  --seed 1337 \
  --clean
```

This creates 50 synthetic bank-detail-change scams, 50 synthetic verified
bank-detail-change notices, and 50 synthetic `SAFE` invoice notices with train,
validation, and test splits. Use it to exercise the analyzer and future ML code.
Do not treat synthetic-only results as production-quality evidence.

Add public-advisory-derived examples for `VERIFY` and `DO_NOT_PAY`:

```bash
python scripts/payment_dataset.py seed-public-advisory \
  --dataset data/payment_scam_dataset \
  --do-not-pay-count 10 \
  --verify-count 10 \
  --holdout-do-not-pay-count 3 \
  --holdout-verify-count 3
```

These samples are redacted examples based on public BEC and payment-redirection
warning patterns from:

- [Scamwatch business email compromise scams](https://www.scamwatch.gov.au/types-of-scams/business-email-compromise-scams)
- [Australian Cyber Security Centre business email compromise](https://www.cyber.gov.au/threats/types-threats/business-email-compromise)
- [FBI business email compromise fraud alert](https://www.fbi.gov/contact-us/field-offices/denver/news/press-releases/business-e-mail-compromise-fraud-alert)
- [Sublime Security BEC fake invoice analysis](https://sublime.security/blog/business-email-compromise-fake-invoice-16800)

They are not copied from private mail and should be used as reproducible
coverage for decision handling. They improve the development dataset, but real
redacted inbox/client examples remain the better evidence before publishing
external product metrics.

Recommended minimum collection:

| Scenario | Scam | Legitimate |
|---|---:|---:|
| Bank detail change | 50 | 50 |
| Supplier impersonation | 50 | 25 |
| Executive transfer request | 50 | 25 |
| Overdue invoice pressure | 50 | 50 |
| Payment portal link | 30 | 30 |
| Invoice attachment | 50 | 50 |
| Normal business non-payment mail | 0 | 100 |

Label rules:

- `PAYMENT_SCAM`: confirmed malicious, red-team generated, or synthetic attack sample.
- `LEGITIMATE_PAYMENT`: real or synthetic normal invoice, remittance, statement, or verified bank-detail change.
- `NON_PAYMENT`: normal clean business mail with no payment context.
- `payment_decision=DO_NOT_PAY`: payment must be blocked.
- `payment_decision=VERIFY`: payment can continue only after out-of-band supplier or executive verification.
- `payment_decision=SAFE`: no material payment-risk signal is expected.

## Product Positioning

Working name:

> Payment Scam Firewall powered by the phishing detector

Simple pitch:

> Stops invoice scams before your business pays the wrong account.

This keeps the project connected to detection engineering while making the output easier for SMEs to understand and buy.
