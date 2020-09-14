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

### Set up infrastructure 

Define necessary environment variables in the terminal session for convenience.
```
PROJECT=$(gcloud config get-value project)
REGION=us-east1 # change to what fits your situation
ZONE=${REGION}-b
CLUSTER=adapter-load-test # change to the desired name
gcloud config set compute/region $REGION 
gcloud config set compute/zone $ZONE
```

Make sure the following APIs are enabled by running:
```
gcloud services enable \
    cloudbuild.googleapis.com \
    compute.googleapis.com \
    container.googleapis.com \
    containeranalysis.googleapis.com \
    containerregistry.googleapis.com 
```

Create a GKE cluster and configure `kubectl` context. Below is an example command:
```
gcloud container clusters create $CLUSTER \
    --zone $ZONE \
    --scopes "https://www.googleapis.com/auth/cloud-platform" \
    --num-nodes "4" \
    --enable-autoscaling --min-nodes "4" \
    --max-nodes "10" \
    --addons HorizontalPodAutoscaling,HttpLoadBalancing

gcloud container clusters get-credentials $CLUSTER \
    --zone $ZONE \
    --project $PROJECT
```

Everything that is created later will be in the namespace `apigee`, which needs to be created now.

```
kubectl create namespace apigee
```

### Build and submit project-specific Docker images

Build and upload the docker images of the mock apigee and target servers to the project's container registry.
```
gcloud builds submit --tag gcr.io/$PROJECT/apigee-mock:latest apigee/.
gcloud builds submit --tag gcr.io/$PROJECT/target-mock:latest target/.
```

Optionally, a local image of the Apigee Envoy Adapter can also be built in the same fashion.
```
gcloud builds submit --tag gcr.io/$PROJECT/apigee-envoy-adapter:latest ../.
```

### Prepare self-signed certs

We use self-signed certificates to enable TLS for the mock Apigee server and the Envoy adapter server. All the relevant configurations are set to allow insecure and CN-based certs (not for production use!). Below are example commands to generate self-signed certs. One simply needs to modify the output directories to some appropriate locations.

```
openssl req  -nodes -new -x509 -keyout ./mock-apigee/tls.key -out \
    ./mock-apigee/tls.crt -subj '/CN=mock-apigee.apigee.svc.cluster.local' -days 3650
openssl req  -nodes -new -x509 -keyout ./adapter/tls.key -out \
    ./adapter/tls.crt -subj '/CN=apigee-remote-service-envoy.apigee.svc.cluster.local' -days 3650
```

The base64 encoded certs and keys need to be embedded into the k8s secrets via:
```
sed -i -e "s/{{base64 encoded crt}}/$CRT/g" k8s-files/apigee-mock-config.yaml | CRT=$(base64 your-mock-apigee-crt --wrap=0)
sed -i -e "s/{{base64 encoded key}}/$KEY/g" k8s-files/apigee-mock-config.yaml | KEY=$(base64 your-mock-apigee-key --wrap=0)
sed -i -e "s/{{base64 encoded crt}}/$CRT/g" k8s-files/adapter-config.yaml | CRT=$(base64 your-envoy-adapter-crt --wrap=0)
sed -i -e "s/{{base64 encoded key}}/$KEY/g" k8s-files/adapter-config.yaml | CRT=$(base64 your-envoy-adapter-key --wrap=0)
```

### Apply ConfigMaps

The configurations for the envoy proxy, apigee adapter as well as the `locustfile.py` are embedded in ConfigMap yaml files. They are already good to start the basic tests. But one can edit them to fit the actual needs.

Apply the ConfigMaps first to the GKE cluster:
```
kubectl apply -f k8s-files/envoy-config.yaml
kubectl apply -f k8s-files/adapter-config.yaml
kubectl apply -f k8s-files/locustfile-config.yaml
```

### Set up node affinity with pods

To make the test more realistic, one would want the mock servers and locust clients to be residing in different nodes from the adapter. This can be achieved by tainting the nodes with the following labels. The corresponding tolerations are already put in the deployments yaml files. Ideally there should be at least four nodes available, or five with prometheus server. Replace `$(node-#)` with actual node names.
```
kubectl taint nodes $(node-1) adapter=true:NoSchedule
kubectl taint nodes $(node-2) mock-target=true:NoSchedule
kubectl taint nodes $(node-3) mock-apigee=true:NoSchedule
kubectl taint nodes $(node-4) locust=true:NoSchedule
kubectl taint nodes $(node-5) prometheus=true:NoSchedule
```

### Apply Deployments

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

### Start load testing

Along with the locust manager deployment, a load balancer is configured to expose the manager ports. The external IP can be extracted using
```
LB_IP=$(kubectl get svc -n apigee locust-manager -o yaml | grep ip | awk -F":" '{print $NF}')
```
Once everything is ready, one can open `http://$LB_IP:8089` in a web browser to start the load tests.

### Clean up

After testing is completed, one can delete the cluster to avoid unexpected billing:
```
gcloud container clusters delete $CLUSTER --zone $ZONE
```

### Monitor Prometheus Metrics (optional)

It is very useful to set up a Prometheus server scraping the metrics of the Apigee Envoy Adapter pod. The configuration files for deploying a Prometheus server are prepared in the `./prometheus` folder.

First of all, one needs to create a k8s service account with the cluster-admin role for the Prometheus server to be able to call the k8s API server. And a service account token should be created manually (such that its name is free of hash) as a k8s secret for the server to read.

```
kubectl create serviceaccount -n apigee prometheus
kubectl create clusterrolebinding prometheus \
  --clusterrole=cluster-admin \
  --serviceaccount=apigee:prometheus
kubectl apply -f prometheus/service-account-token.yaml
```

Secondly, one can apply the ConfigMap containing the prometheus configuration file and deploy the server.

```
kubectl apply -f prometheus/prometheus-config.yaml
kubectl apply -f prometheus/prometheus-server.yaml
```

Now the port of Prometheus server can be forwarded out and visualization can be done using [Grafana](https://grafana.com/grafana/download/).

```
kubectl port-forward -n apigee $(prometheus-pod-name) 9090:9090
```

If one would like to deploy grafana within the same cluster, they may simply run
```
kubectl apply -f prometheus/grafana.yaml
```
and connect to Grafana web UI by forwarding the port `3000` out. The Prometheus server is already exposed as a service through port `9090` to be configured as the data source.