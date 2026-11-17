variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "region" {
  description = "The GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "network_name" {
  description = "Name of the persistent test VPC created from the network/ Terraform configuration"
  type        = string
  default     = "tas-e2e-test"
}

variable "subnetwork_name" {
  description = "Name of the persistent test subnet created from the network/ Terraform configuration"
  type        = string
  default     = "tas-e2e-test"
}

variable "vm_max_runtime_minutes" {
  description = "Minutes before Compute Engine deletes the running test VM"
  type        = number
  default     = 90

  validation {
    condition     = var.vm_max_runtime_minutes >= 30 && var.vm_max_runtime_minutes <= 240 && floor(var.vm_max_runtime_minutes) == var.vm_max_runtime_minutes
    error_message = "vm_max_runtime_minutes must be a whole number between 30 and 240."
  }
}
