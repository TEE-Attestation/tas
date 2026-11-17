locals {
  e2e_labels = { purpose = "tas-cvm-e2e" }
  # Zero-role guest SA created once, outside this workspace, so per-run destroys never delete it.
  guest_service_account_id = "tas-e2e-test-guest@${var.project_id}.iam.gserviceaccount.com"
}

data "google_service_account" "guest" {
  account_id = local.guest_service_account_id
}

data "google_compute_network" "tas_e2e" {
  name = var.network_name
}

data "google_compute_subnetwork" "tas_e2e" {
  name   = var.subnetwork_name
  region = var.region
}

resource "google_compute_instance" "tas_cvm" {
  name         = "tas-e2e-test-${lower(terraform.workspace)}"
  machine_type = "n2d-standard-2"
  zone         = var.zone
  labels       = local.e2e_labels

  boot_disk {
    auto_delete = true

    initialize_params {
      image  = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2604-lts-amd64"
      size   = 20
      type   = "pd-balanced"
      labels = local.e2e_labels
    }
  }

  network_interface {
    network    = data.google_compute_network.tas_e2e.self_link
    subnetwork = data.google_compute_subnetwork.tas_e2e.self_link
  }

  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "SEV_SNP"
  }

  scheduling {
    on_host_maintenance         = "TERMINATE"
    automatic_restart           = false
    instance_termination_action = "DELETE"

    max_run_duration {
      seconds = var.vm_max_runtime_minutes * 60
    }
  }

  # Untrusted PR code runs on this VM, so it must not inherit the project's default Compute SA.
  service_account {
    email  = data.google_service_account.guest.email
    scopes = []
  }

  tags = ["tas-cvm"]
}

output "instance_name" {
  description = "The name of the Confidential VM"
  value       = google_compute_instance.tas_cvm.name
}

output "project_id" {
  description = "The GCP project containing the Confidential VM"
  value       = var.project_id
}

output "zone" {
  description = "The zone containing the Confidential VM"
  value       = var.zone
}
