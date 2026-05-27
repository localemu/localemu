# Terraform test suite

We regularly run the test suite of the Terraform AWS provider against LocalEmu to test the compatibility of LocalEmu to Terraform. To achieve that, we have a dedicated [GitHub action](https://github.com/localemu/localemu-terraform-test/blob/main/.github/workflows/main.yml) on [LocalEmu](https://github.com/localemu/localemu), which executes the allow listed set of tests of [hashicorp/terraform-provider-aws](https://github.com/hashicorp/terraform-provider-aws/).
