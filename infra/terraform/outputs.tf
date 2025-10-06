output "service_account_email" {
  description = "Email of the created service account"
  value       = google_service_account.lab_sa.email
}

output "audit_log_bucket" {
  description = "Name of the audit logs storage bucket"
  value       = google_storage_bucket.audit_logs.name
}
