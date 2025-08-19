package policy
import rego.v1
default hardware := 97
default configuration := 36
default executables := 33

##### TPM
hardware := 2 if {
  input.tpm.svn in data.reference.tpm_svn
}

tpm_pcrs_valid if {
  lower(input.tpm.pcrs[4]) in data.reference.tpm_pcr4
  lower(input.tpm.pcrs[7]) in data.reference.tpm_pcr7
  lower(input.tpm.pcrs[14]) in data.reference.tpm_pcr14
}

executables := 3 if tpm_pcrs_valid
configuration := 2 if tpm_pcrs_valid
