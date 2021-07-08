## Integration test scripts

### Exit code definition

1 - configuration generation error

2 - local target call error with API key

3 - local target call error with JWT

4 - K8s/Istio target call error with API key

5 - K8s/Istio target call error with JWT

6 - other errors during tests running on k8s/Istio

7 - other errors during tests running locally

8 - error provisioning with Hybrid

9 - error provisioning with CG SaaS

10 - error during load tests

*NOTE*: The test scripts serve the Kokoro builds internally. As of now they do not create a sandbox environment. Instead they rely on existing Apigee platforms and credentials. Therefore, running the scripts locally still require permission to access those resources and they are not meant for general use.