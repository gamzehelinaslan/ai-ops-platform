# Outputs: which info we wanna see after apply
# will read GKE cluster endpoint from here

output "cluster_name" {
  value = var.cluster_name
}

output "region" {
  value = var.region
}
