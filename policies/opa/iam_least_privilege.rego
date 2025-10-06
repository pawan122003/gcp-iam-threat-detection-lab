package gcp.iam.least_privilege

# Deny overly permissive roles
deny[msg] {
  input.bindings[_].role == "roles/owner"
  msg := "Owner role grants excessive permissions. Use specific roles instead."
}

deny[msg] {
  input.bindings[_].role == "roles/editor"
  msg := "Editor role grants excessive permissions. Use specific roles instead."
}

# Deny public IAM bindings
deny[msg] {
  input.bindings[_].members[_] == "allUsers"
  msg := "Public access (allUsers) detected. This violates least privilege."
}

deny[msg] {
  input.bindings[_].members[_] == "allAuthenticatedUsers"
  msg := "Public access (allAuthenticatedUsers) detected. This violates least privilege."
}

# Warn on service accounts with admin roles
warn[msg] {
  binding := input.bindings[_]
  contains(binding.role, "admin")
  member := binding.members[_]
  startswith(member, "serviceAccount:")
  msg := sprintf("Service account %s has admin role %s", [member, binding.role])
}
