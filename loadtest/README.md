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

# Distributed load testing on GKE

Define necessary environment variables in the terminal session for convenience.
```
$ PROJECT=$(gcloud config get-value project)
$ REGION=us-east1 # change to what fits your situation
$ ZONE=${REGION}-b
$ CLUSTER=gke-load-test
$ TARGET=${PROJECT}.appspot.com
$ gcloud config set compute/region $REGION 
$ gcloud config set compute/zone $ZONE
```

Make sure the following APIs are enabled by running:
```
$ gcloud services enable \
    cloudbuild.googleapis.com \
    compute.googleapis.com \
    container.googleapis.com \
    containeranalysis.googleapis.com \
    containerregistry.googleapis.com 
```

Build and upload the docker images of the mock apigee and target servers to the project's container registry.
```
$ gcloud builds submit --tag gcr.io/$PROJECT/apigee-mock:latest ../apigee/.
$ gcloud builds submit --tag gcr.io/$PROJECT/target-mock:latest ../target/.
```

The configurations for the envoy proxy, apigee adapter as well as the `locustfile.py` are embedded in ConfigMap yaml files. They are already good to start the basic tests. But one can edit them to fit the actual needs.

Apply the ConfigMaps first to the GKE cluster:
```
kubectl apply -f k8s-files/envoy-config.yaml
kubectl apply -f k8s-files/adapter-config.yaml
kubectl apply -f k8s-files/locustfile-config.yaml
```

Replace the project ID in the following k8s configuration files. One can also customize other details as needed.
```
sed -i -e "s/\[PROJECT_ID\]/$PROJECT/g" k8s-files/target-server.yaml
sed -i -e "s/\[PROJECT_ID\]/$PROJECT/g" k8s-files/apigee-mock-server.yaml
```

Apply the rest to the GKE cluster:
```
kubectl apply -f k8s-files/apigee-mock-server.yaml
kubectl apply -f k8s-files/target-server.yaml
kubectl apply -f k8s-files/apigee-envoy-adapter.yaml
kubectl apply -f k8s-files/locust-manager.yaml
kubectl apply -f k8s-files/locust-worker.yaml
```

By default, the number of locust workers is 20.

Along with the locust manager deployment, a load balancer is configured to expose the manager ports. Once everything is ready, one can open `http://$LB_IP:8089` in a web browser to start the load tests.