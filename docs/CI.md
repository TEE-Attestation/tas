# TAS CI documentation

## TAS CVM end-to-end test

### Overview

The CVM end-to-end (E2E) test checks hardware-backed attestation on a real AMD
SEV-SNP Confidential VM. Each run provisions a fresh CVM with Terraform, runs a
guest script over IAP SSH that installs and builds the latest TAS tools and
helper repositories, starts TAS with a mock secret backend, has `tas_agent`
request a secret, checks that the released secret matches the stored one, and
destroys the VM.

Unit tests cannot cover this path because they do not collect real TEE evidence.
Provisioning creates billable GCP resources. The example workflow's triggers and
GCP settings are not defaults; review IAM, cost controls, and cleanup before
enabling it in another project.

### Components

| Path | Purpose |
|---|---|
| `.github/workflows/tas-cvm-e2e.yml` | Manually dispatched workflow. Validates the repository branch head against an explicit commit SHA and calls the runner. |
| `ci/tas-cvm-e2e/run.sh` | Runner. Provisions the VM, runs the guest test over IAP, and destroys resources on exit. |
| `ci/tas-cvm-e2e/check.sh` | Non-provisioning checks: shell syntax and Terraform fmt, init, and validate. |
| `ci/tas-cvm-e2e/terraform/cvm/` | Terraform for one CVM: `main.tf` (instance and data sources), `variables.tf`, `provider.tf`, and `.terraform.lock.hcl`. |
| `ci/tas-cvm-e2e/guest/setup_and_test_tas.sh` | Guest test that runs on the VM. |
| `ci/tas-cvm-e2e/logs/` | Per-run logs. Created at runtime and git-ignored. |
| `.gitignore` | Ignores Terraform state, `.terraform/`, `*.tfvars`, and the logs directory. |

### How a run works

- **Workflow:** A manually dispatched GitHub Actions job. It takes the TAS
  repository URL, branch, and `expected_sha`; it checks the branch currently
  resolves to that exact commit, then runs the test on that commit. This works
  with public fork branches as well as branches in the main repository. It authenticates to GCP through
  Workload Identity Federation (WIF) and runs in the `tas-cvm-e2e` environment.
  Timeouts: 180 minutes for the job, 165 for provisioning and the test, 65 for
  the remote test. A final step deletes the run's VM if it still exists.
- **Runner (`run.sh`):** Validates the inputs, creates a Terraform workspace
  named `tas-e2e-<run id>`, plans and applies, waits for IAP SSH, copies in and
  runs the guest script, then destroys the resources on exit. If destroy fails,
  the workspace is kept and the VM details are printed.
- **Terraform (`terraform/cvm/`):** Creates one `n2d-standard-2` SEV-SNP VM with
  a 20 GB auto-delete boot disk from the public Ubuntu 26.04 LTS image family. The VM
  has a maximum
  runtime (default 180 minutes) so Compute Engine deletes it if the runner never
  cleans up. It runs as the guest service account with no OAuth scopes, so
  untrusted test code cannot use the default Compute service account.
- **Guest test (`guest/setup_and_test_tas.sh`):** Runs on the VM. It installs
  build prerequisites and stable Rust, detects SEV or TDX, fetches TAS at
  `TAS_COMMIT` and the helper repos at their default-branch commits, then
  builds `tas_agent` and `tas-policy` from their default branches. It starts
  the TAS server with a mock secret backend, creates a policy, and runs
  `tas_agent` under sudo. It prints
  `E2E ATTESTATION TEST PASSED` only if the released secret matches the stored one.
  Key and policy IDs include the run ID, since the create-only commands reject
  reuse.
- **Local checks (`check.sh`):** Syntax checks the scripts and runs Terraform
  format, init, and validate. It provisions nothing.

### GCP project setup

These must exist before the first run. Terraform reads them but does not create them.

- A dedicated test GCP project (never production) with the Compute Engine, IAP,
  IAM, and Security Token Service APIs enabled.
- A VPC and regional subnet named `tas-e2e-test` in the runner's region.
- A firewall rule allowing TCP 22 from IAP's range `35.235.240.0/20`, with no
  public SSH. The guest also needs outbound access to GitHub and package sources.
- Ubuntu 26.04 LTS image family `ubuntu-2604-lts-amd64` from the
  `ubuntu-os-cloud` project. This image family supports AMD SEV-SNP. No custom
  image or additional IAM permissions for image publishing are required.
- A guest service account, `tas-e2e-test-guest`, with no IAM roles.
- A deployer service account that creates and deletes the VM, uses IAP SSH, and
  reads the image and network. Use the narrowest roles that work; Terraform
  validation does not prove least privilege.
- A Workload Identity Federation pool and GitHub OIDC provider, restricted to
  your repository and trusted workflow, granting `roles/iam.workloadIdentityUser`
  on the deployer account.
- A GitHub Environment named `tas-cvm-e2e` with required reviewers and a
  deployment-branch policy limited to `main`.

The workflow's project, WIF provider, service account, and region and zone are
example values to replace.

### Runner inputs

| Input | Default | Purpose |
|---|---|---|
| `TF_VAR_project_id` | Required unless a variable file is used | GCP project ID |
| `TF_VAR_region` / `TF_VAR_zone` | `us-central1` / `us-central1-a` | Location of the subnet and VM |
| `TF_VAR_network_name` / `TF_VAR_subnetwork_name` | `tas-e2e-test` | Existing VPC and subnet |
| `TAS_REPO_URL` | Required | HTTPS GitHub URL of the TAS repository |
| `TAS_BRANCH` | Required | Branch associated with the tested revision |
| `TAS_COMMIT` | Required | Lowercase 40-character commit SHA to test |
| `TAS_VM_MAX_RUNTIME_MINUTES` | `180` | Runtime limit in minutes, 30–240 |
| `TF_VARS_FILE` | `ci/tas-cvm-e2e/terraform/cvm/terraform.tfvars` | Optional Terraform variable file |

Keep variable files out of version control and do not store credentials in them.

### Running locally

From the repository root, run the non-provisioning checks (needs Bash and
Terraform):

```bash
bash ci/tas-cvm-e2e/check.sh
```

For the full test, also install gcloud, Git, jq, and GNU `timeout`. Authenticate
with `gcloud auth login` and `gcloud auth application-default login`, use an
identity that can create/delete the VM and open an IAP tunnel, and set
`TAS_REPO_URL`, `TAS_BRANCH`, and the exact `TAS_COMMIT` SHA before running
`bash ci/tas-cvm-e2e/run.sh`. The commit is required to pin the exact source
tested. The GCP project must allow egress from the guest to GitHub, Ubuntu
package repositories, Rust distribution servers, and Python package indexes;
no image-family setup or image-publishing permissions are needed. Logs go to
`ci/tas-cvm-e2e/logs/`; review and redact them before sharing.
