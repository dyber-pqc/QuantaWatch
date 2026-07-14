# QuantaWatch — Terraform deployment (Helm release onto an existing cluster).
#
# Deploys the chart in ../helm/quantawatch. Assumes kubeconfig context is
# already selected (or pass one via var.kube_config_path/var.kube_context).

terraform {
  required_version = ">= 1.3"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24"
    }
  }
}

provider "kubernetes" {
  config_path    = var.kube_config_path
  config_context = var.kube_context
}

provider "helm" {
  kubernetes {
    config_path    = var.kube_config_path
    config_context = var.kube_context
  }
}

resource "kubernetes_namespace" "quantawatch" {
  count = var.create_namespace ? 1 : 0
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/part-of" = "quantawatch"
    }
  }
}

resource "helm_release" "quantawatch" {
  name      = var.release_name
  chart     = "${path.module}/../helm/quantawatch"
  namespace = var.namespace

  create_namespace = false
  depends_on       = [kubernetes_namespace.quantawatch]

  # Base values file (optional) + inline overrides.
  values = var.values_file != "" ? [file(var.values_file)] : []

  set {
    name  = "image.repository"
    value = var.image_repository
  }

  set {
    name  = "image.tag"
    value = var.image_tag
  }

  set {
    name  = "ingress.enabled"
    value = var.ingress_enabled
  }

  dynamic "set" {
    for_each = var.ingress_enabled ? [1] : []
    content {
      name  = "ingress.host"
      value = var.ingress_host
    }
  }

  set {
    name  = "persistence.size"
    value = var.storage_size
  }

  dynamic "set" {
    for_each = var.storage_class != "" ? [1] : []
    content {
      name  = "persistence.storageClass"
      value = var.storage_class
    }
  }

  # Secrets — supplied via sensitive vars, rendered into the chart's Secret.
  # Prefer -var-file with a git-ignored *.tfvars, or a secrets manager.
  dynamic "set_sensitive" {
    for_each = var.secret_env
    content {
      name  = "secretEnv.${set_sensitive.key}"
      value = set_sensitive.value
    }
  }

  # Inline config file override (full quantawatch.yaml), if provided.
  dynamic "set" {
    for_each = var.config_file != "" ? [1] : []
    content {
      name  = "config"
      value = file(var.config_file)
      type  = "string"
    }
  }
}
