# CiphR API Contract

This document provides the exact REST API specifications for the CiphR Fraud Intelligence backend, designed for the frontend developer integration.

## Base Information
- **Base URL**: `http://localhost:8000/api/v1`
- **Request Format**: `application/json` (unless multipart upload)
- **Response Format**: `application/json`

---

## 1. Samples

### Upload Sample
Uploads an Android APK and queues it for the intelligence pipeline.
- **Method**: `POST`
- **URL**: `/samples/upload`
- **Content-Type**: `multipart/form-data`
- **Form Fields**:
  - `file` (Required): The actual `.apk` file binary
  - `source` (Optional, string): Identifier for where the APK came from (e.g., "manual_upload")
  - `submitted_by` (Optional, string): The user submitting the file
- **Response**:
  ```json
  {
    "id": "uuid-string",
    "filename": "app.apk",
    "sha256": "354b56605...",
    "size": 12345,
    "source": "manual_upload",
    "submitted_by": null,
    "status": "QUEUED",
    "created_at": "2026-09-09T00:00:00Z",
    "updated_at": "2026-09-09T00:00:00Z"
  }
  ```
- **Duplicate Behavior**: If an exact SHA-256 duplicate is uploaded, the backend dynamically returns the *existing* sample record with a `200 OK`. 
- **Validation Errors**: Yields `400 Bad Request` if the file is excessively large, not a zip archive, or malformed.

### List Samples
- **Method**: `GET`
- **URL**: `/samples`
- **Query Parameters**:
  - `skip` (int, default: 0)
  - `limit` (int, default: 20)
  - `status` (string, optional filter: e.g., "COMPLETED")
- **Response**:
  ```json
  {
    "items": [ { /* Sample Object */ } ],
    "total": 100,
    "page": 1,
    "size": 20
  }
  ```

### Get Sample Status
Returns real-time pipeline status for the frontend poller.
- **Method**: `GET`
- **URL**: `/samples/{sample_id}/status`
- **Response**:
  ```json
  {
    "sample_id": "uuid-string",
    "status": "COMPLETED", 
    "stages": {
      "validation": "completed",
      "pipeline": "COMPLETED",
      "error": null
    }
  }
  ```
- **Statuses**:
  - `QUEUED`: Waiting to begin analysis.
  - `ANALYZING`: Running Androguard extraction.
  - `CORRELATING`: Analyzing campaigns.
  - `GENERATING_NARRATIVE`: Waiting for LLM output.
  - `COMPLETED`: Pipeline successful.
  - `FAILED`: Pipeline halted due to corruption (check `error`).

### Get Sample Analysis
Returns the extracted metadata, risk score, and threat narrative.
- **Method**: `GET`
- **URL**: `/samples/{sample_id}/analysis`
- **Response**:
  ```json
  {
    "id": "uuid-string",
    "sample_id": "uuid-string",
    "status": "COMPLETED",
    "package_name": "io.appium.android.apis",
    "app_name": "API Demos",
    "version_name": "3.1.0",
    "version_code": "18",
    "min_sdk": "17",
    "target_sdk": "28",
    "tlsh": "MOCK_TLSH_354b566...",
    "certificate_fingerprint": "a40da80a5...",
    "risk_score": 20,
    "threat_narrative": "The analyzed application... (plaintext format)",
    "error_message": null,
    "started_at": "2026-09-09T00:00:00Z",
    "completed_at": "2026-09-09T00:00:02Z"
  }
  ```

### Get Sample Findings
Returns specific risk evidence flagged by heuristics (mapped to MITRE if possible).
- **Method**: `GET`
- **URL**: `/samples/{sample_id}/findings`
- **Response**:
  ```json
  [
    {
      "id": "uuid-string",
      "sample_id": "uuid-string",
      "title": "SMS Permission Requested",
      "description": "App can read or send SMS messages...",
      "severity": "HIGH",
      "category": "Permission",
      "evidence": "SMS Permissions",
      "mitre_technique_id": "T1636",
      "confidence": 1.0
    }
  ]
  ```

---

## 2. Campaigns

### List Campaigns
- **Method**: `GET`
- **URL**: `/campaigns`
- **Query Parameters**: `skip`, `limit`
- **Response**: Paginated response of Campaign objects.

### Get Campaign Graph
Returns a fully structured network graph representation for visual frontends (e.g. `vis-network`).
- **Method**: `GET`
- **URL**: `/campaigns/{campaign_id}/graph`
- **Response**:
  ```json
  {
    "nodes": [
      {
        "id": "campaign-uuid",
        "type": "campaign",
        "label": "Campaign-a40da80a"
      },
      {
        "id": "sample-uuid",
        "type": "sample",
        "label": "app.apk"
      }
    ],
    "edges": [
      {
        "source": "sample-uuid",
        "target": "campaign-uuid",
        "relationship": "same_certificate",
        "confidence": 1.0
      }
    ]
  }
  ```

---

## Error Handling
The backend uses unified error objects returning consistent code formats instead of raw stack traces.
- **Example Response (400 Bad Request)**:
  ```json
  {
    "error": {
      "code": "INVALID_APK",
      "message": "The file is not a valid ZIP/APK archive."
    }
  }
  ```
