output "release_name" {
  description = "Deployed Helm release."
  value       = helm_release.quantawatch.name
}

output "namespace" {
  description = "Namespace QuantaWatch is running in."
  value       = var.namespace
}

output "status" {
  description = "Helm release status."
  value       = helm_release.quantawatch.status
}

output "admin_api_portforward" {
  description = "Command to reach the admin API locally."
  value       = "kubectl -n ${var.namespace} port-forward svc/${helm_release.quantawatch.name} 9091:9091"
}

output "dashboard_url" {
  description = "Dashboard URL when ingress is enabled."
  value       = var.ingress_enabled ? "https://${var.ingress_host}" : "ingress disabled — use port-forward"
}
