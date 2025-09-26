# Integration tests

The integration tests evaluate if the operator is functioning correctly. Each integration tests is deployed in in a new
namespace in a way to guarantee the isolation of a test from the other, and to be able to run them in parallel.
The operator is installed in each namespace before running the actual tests with the `setup` function. 
Upon a successful test, the namespace is cleaned up, otherwise it is kept for inspecting the state.

## Setup the integration tests locally
Run the tests locally with kind:
```
make cluster-up
REGISTRY=localhost:5000 make manifests
make push
make integration-tests
```
