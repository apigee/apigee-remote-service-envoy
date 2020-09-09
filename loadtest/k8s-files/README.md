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

Replace the project ID in the k8s configuration files.
```
sed -i -e "s/\[PROJECT_ID\]/$PROJECT/g" k8s-config/apigee-mock-server.yaml
```