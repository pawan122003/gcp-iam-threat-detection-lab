terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Service Account for lab purposes
resource "google_service_account" "lab_sa" {
  account_id   = "iam-threat-detection-lab"
  display_name = "IAM Threat Detection Lab Service Account"
  description  = "Service account for demonstrating IAM security controls"
}

# Log sink for audit logs
resource "google_logging_project_sink" "iam_audit_sink" {
  name        = "iam-audit-log-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  
  filter = "protoPayload.methodName=\"SetIamPolicy\" OR protoPayload.methodName=\"google.iam.admin.v1.CreateServiceAccountKey\""
  
  unique_writer_identity = true
}

# Storage bucket for audit logs
resource "google_storage_bucket" "audit_logs" {
  name     = "${var.project_id}-iam-audit-logs"
  location = var.region
  
  uniform_bucket_level_access = true
  
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}

# Grant storage permissions to log sink
resource "google_storage_bucket_iam_member" "log_sink_writer" {
  bucket = google_storage_bucket.audit_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.iam_audit_sink.writer_identity
}

# INTENTIONAL SECURITY VIOLATION: Over-permissive IAM role for demo
resource "google_project_iam_member" "overpermissive_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.lab_sa.email}"
}
