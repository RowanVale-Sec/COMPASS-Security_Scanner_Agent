terraform {
  backend "gcs" {
    # The bucket and prefix are supplied at init time:
    #   terraform init -backend-config=environments/prod/backend.tfvars
    # so the same root config can target multiple environments without edits.
  }
}
