# Mock Server

This mock server runs as a test server and generates products.

## Running services

Assumes running from this directory.

### Mock Apigee (6000)

    go run apigee/main.go -addr :6000 -num-products 300

### OK Target (6001)

    go run target/main.go -addr :6001

### Remote Service (5000,5001)

    go run ../main.go -c config.yaml

### Envoy (8080)

    envoy -c envoy/config.yaml

## curl client

Any path is fine.
For auth, host much match x-api-key and be product-n where n in range.

    # forbidden
    curl -i http://localhost:8080

    # forbidden
    curl -i http://localhost:8080 -Hhost:whatever -Hx-api-key:whatever

    # ok
    curl -i http://localhost:8080 -Hhost:product-1 -Hx-api-key:product-1

## Locust driver

    cd locust
    locust --config master.conf
