# Unit testing Kubernetes API interaction with MockClient

The trusted-cluster-operator makes numerous calls to the Kubernetes API in its code.
Alongside integration tests, the operator's functions are also unit tested, which requires mocking the responses of the API.

For a test, responses are sent based on a function that takes the request as well as a counter that is incremented upon each request.
The latter is useful for testing the expected order of requests, plus ensuring all the expected requests were sent.

## Example: `trustee::update_reference_values` in the successful case

In the successul case, `trustee::update_reference_values` performs the following API interactions:

| Count | Action                                                                 | Test                                           |
|-------|------------------------------------------------------------------------|------------------------------------------------|
| 0     | Retrieve the ConfigMap of reference image PCR values to determine them | HTTP GET, path contains PCR ConfigMap name     |
| 1     | Read the Trustee ConfigMap and update its reference values             | HTTP GET, path contains Trustee ConfigMap name |
| 2     | Replace the ConfigMap with the updated one                             | HTTP PUT, path contains Trustee ConfigMap name |


A mock endpoint that checks these things can be defined like this:

```rust
let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
    (0, &Method::GET) => {
        assert!(req.uri().path().contains(PCR_CONFIG_MAP));
        Ok(serde_json::to_string(&dummy_pcrs_map()).unwrap())
    }
    (1, &Method::GET) | (2, &Method::PUT) => {
        assert!(req.uri().path().contains(TRUSTEE_DATA_MAP));
        Ok(serde_json::to_string(&dummy_trustee_map()).unwrap())
    }
    _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
};
```

It can then be used with the `count_check!` macro to also ensure the function sent 3 requests and no fewer.
This macro establishes an atomic counter and compares against it; assertions in a Drop implementation would not fire back to the test thread.

```rust
count_check!(3, clos, |client| {
    let ctx = generate_rv_ctx(client);
    assert!(update_reference_values(ctx).await.is_ok());
});
```
