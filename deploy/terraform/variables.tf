variable "kube_config_path" {
  description = "Path to kubeconfig."
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "kubeconfig context to use (empty = current)."
  type        = string
  default     = ""
}

variable "release_name" {
  description = "Helm release name."
  type        = string
  default     = "quantawatch"
}

variable "namespace" {
  description = "Kubernetes namespace."
  type        = string
  default     = "quantawatch"
}

variable "create_namespace" {
  description = "Create the namespace before installing."
  type        = bool
  default     = true
}

variable "image_repository" {
  description = "Gateway image repository."
  type        = string
  default     = "ghcr.io/dyber/quantawatch"
}

variable "image_tag" {
  description = "Gateway image tag."
  type        = string
  default     = "1.0.0"
}

variable "ingress_enabled" {
  description = "Expose via an Ingress."
  type        = bool
  default     = false
}

variable "ingress_host" {
  description = "Ingress FQDN (required when ingress_enabled)."
  type        = string
  default     = "quantawatch.example.com"
}

variable "storage_size" {
  description = "PVC size for the SQLite store, keys, and audit chain."
  type        = string
  default     = "10Gi"
}

variable "storage_class" {
  description = "StorageClass for the PVC (empty = cluster default)."
  type        = string
  default     = ""
}

variable "values_file" {
  description = "Optional path to a base Helm values file."
  type        = string
  default     = ""
}

variable "config_file" {
  description = "Optional path to a full quantawatch.yaml to render into the ConfigMap."
  type        = string
  default     = ""
}

variable "secret_env" {
  description = "Map of ENV_VAR_NAME => secret value, rendered into the chart Secret (e.g. ANTHROPIC_API_KEY, QW_WEBHOOK_SECRET)."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "fortressql_enabled" {
  description = "Deploy FortressQL (PQC PostgreSQL) in-cluster and point the gateway's store at it over PQC TLS."
  type        = bool
  default     = false
}

variable "fortressql_password" {
  description = "Password for the FortressQL role QuantaWatch connects as. Supply via -var-file / secrets manager; kept in a Kubernetes Secret."
  type        = string
  default     = ""
  sensitive   = true
}
