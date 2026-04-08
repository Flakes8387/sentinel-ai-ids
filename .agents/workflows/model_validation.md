---
description: Test detection logic against a benchmark dataset before committing changes.
---

# Multi-Stage IDS Validation Workflow

1. Serialize the trained model to `backend/model.joblib`.
2. Run validation using the test dataset to check Detection Rate (> 98%) and False Positive Rate (< 0.5%).
// turbo
3. Extract `alert.log` validation output and append testing results to the documentation.
// turbo
4. Run `pytest` on the detection pipeline to verify that latency metrics remain under 1 second.
