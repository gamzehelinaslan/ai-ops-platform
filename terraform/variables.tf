# Variables: receiving external source values instead of writing hardcode
# just like the values.yaml in Helm

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "europe-west1"
}

variable "cluster_name" {
  description = "GKE cluster name"
  type        = string
  default     = "ai-ops-cluster"
}
