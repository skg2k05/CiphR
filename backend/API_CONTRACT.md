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

### Get Sample Details & Threat Overview
Returns comprehensive sample details including linked campaigns and correlated related samples.
- **Method**: `GET`
- **URL**: `/samples/{sample_id}`
- **Response**:
  ```json
  {
    "id": "uuid-string",
    "filename": "ApiDemos-debug.apk",
    "sha256": "354b56605...",
    "size": 12345,
    "source": "manual_upload",
    "status": "COMPLETED",
    "created_at": "2026-09-12T06:00:00Z",
    "updated_at": "2026-09-12T06:00:05Z",
    "analysis": { /* Analysis Object */ },
    "findings": [ /* Finding Objects */ ],
    "campaigns": [
      {
        "id": "campaign-uuid",
        "name": "Campaign-a40da80a",
        "risk_score": 20,
        "status": "ACTIVE"
      }
    ],
    "related_samples": [
      {
        "sample_id": "related-uuid",
        "filename": "ApiDemos-debug2.apk",
        "sha256": "4a571ee9...",
        "relationship": "same_certificate",
        "confidence": 1.0,
        "reason": "Samples share identical signing certificate fingerprint.",
        "campaign_id": "campaign-uuid",
        "campaign_name": "Campaign-a40da80a"
      }
    ],
    "related_sample_count": 1
  }
  ```

### Get Related Samples (Correlated APKs)
Returns all correlated APK samples linked via shared campaigns, certificates, or indicators.
- **Method**: `GET`
- **URL**: `/samples/{sample_id}/related`
- **Response**:
  ```json
  {
    "sample_id": "uuid-string",
    "total": 1,
    "items": [
      {
        "sample_id": "related-uuid",
        "filename": "ApiDemos-debug2.apk",
        "sha256": "4a571ee9...",
        "relationship": "same_certificate",
        "confidence": 1.0,
        "reason": "Samples share identical signing certificate fingerprint.",
        "campaign_id": "campaign-uuid",
        "campaign_name": "Campaign-a40da80a"
      }
    ]
  }
  ```

### Get Sample Analysis
Returns the extracted metadata, permissions, providers, risk score, and threat narrative.
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
    "certificate_details": {
      "subject": "CN=Android Debug, O=Android, C=US",
      "issuer": "CN=Android Debug, O=Android, C=US",
      "is_debug": true
    },
    "permissions": ["android.permission.INTERNET", "android.permission.READ_CONTACTS"],
    "providers": ["io.appium.android.apis.content.FileProvider"],
    "activities": ["io.appium.android.apis.ApiDemos"],
    "services": [],
    "receivers": [],
    "risk_score": 20,
    "risk_factors": [
      {
        "indicator": "android.permission.READ_CONTACTS",
        "weight": 20,
        "evidence": "Declared in manifest: android.permission.READ_CONTACTS"
      }
    ],
    "threat_narrative": "The analyzed application... (plaintext format)",
    "error_message": null,
    "started_at": "2026-09-09T00:00:00Z",
    "completed_at": "2026-09-09T00:00:02Z"
  }
  ```

### Get Sample Findings
Returns specific risk evidence flagged by heuristics (mapped to MITRE ATT&CK if possible).
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
- **Response**: Paginated response with `sample_count`, `first_seen`, `last_seen`.
  ```json
  {
    "items": [
      {
        "id": "campaign-uuid",
        "name": "Campaign-a40da80a",
        "description": "Automatically correlated threat campaign.",
        "risk_score": 20,
        "status": "ACTIVE",
        "sample_count": 2,
        "first_seen": "2026-09-12T06:00:00Z",
        "last_seen": "2026-09-12T06:05:00Z",
        "created_at": "2026-09-12T06:00:00Z",
        "updated_at": "2026-09-12T06:05:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "size": 20
  }
  ```

### Get Campaign Graph
Returns a fully structured network graph representation for visual frontends (e.g. `vis-network`), including Campaign, Sample, and Certificate nodes with hover metadata.
- **Method**: `GET`
- **URL**: `/campaigns/{campaign_id}/graph`
- **Response**:
  ```json
  {
    "nodes": [
      {
        "id": "campaign-uuid",
        "type": "campaign",
        "label": "Campaign-a40da80a",
        "metadata": { "risk_score": 20, "status": "ACTIVE" }
      },
      {
        "id": "sample-uuid-1",
        "type": "sample",
        "label": "ApiDemos-debug.apk",
        "metadata": { "sha256": "354b566...", "risk_score": 20, "package_name": "io.appium.android.apis" }
      },
      {
        "id": "cert-a40da80a5...",
        "type": "certificate",
        "label": "Cert: a40da80a...",
        "metadata": { "fingerprint": "a40da80a5..." }
      }
    ],
    "edges": [
      {
        "source": "sample-uuid-1",
        "target": "campaign-uuid",
        "relationship": "same_certificate",
        "confidence": 1.0
      },
      {
        "source": "sample-uuid-1",
        "target": "cert-a40da80a5...",
        "relationship": "signed_by",
        "confidence": 1.0
      }
    ]
  }
  ```

### Get Campaign Timeline
Returns chronological lifecycle events derived from real persisted campaign and sample timestamps.
- **Method**: `GET`
- **URL**: `/campaigns/{campaign_id}/timeline`
- **Response**:
  ```json
  {
    "campaign_id": "campaign-uuid",
    "campaign_name": "Campaign-a40da80a",
    "first_seen": "2026-09-12T06:00:00Z",
    "last_seen": "2026-09-12T06:05:00Z",
    "total_events": 4,
    "events": [
      {
        "timestamp": "2026-09-12T06:00:00Z",
        "event_type": "campaign_detected",
        "title": "Threat Campaign Detected",
        "description": "Campaign 'Campaign-a40da80a' registered with initial risk score 20.",
        "sample_id": null,
        "data": { "campaign_id": "campaign-uuid", "risk_score": 20 }
      },
      {
        "timestamp": "2026-09-12T06:00:00Z",
        "event_type": "sample_uploaded",
        "title": "Sample Uploaded",
        "description": "APK sample 'ApiDemos-debug.apk' (SHA-256: 354b56605e...) received.",
        "sample_id": "sample-uuid-1",
        "data": { "filename": "ApiDemos-debug.apk", "sha256": "354b566..." }
      },
      {
        "timestamp": "2026-09-12T06:00:02Z",
        "event_type": "analysis_completed",
        "title": "Static Analysis Completed",
        "description": "Static analysis finished for 'ApiDemos-debug.apk' with risk score 20/100.",
        "sample_id": "sample-uuid-1",
        "data": { "risk_score": 20, "package_name": "io.appium.android.apis" }
      },
      {
        "timestamp": "2026-09-12T06:05:00Z",
        "event_type": "campaign_correlation",
        "title": "Sample Correlated to Campaign",
        "description": "Sample 'ApiDemos-debug2.apk' linked via same_certificate.",
        "sample_id": "sample-uuid-2",
        "data": { "relationship": "same_certificate", "confidence": 1.0 }
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
