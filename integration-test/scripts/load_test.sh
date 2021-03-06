# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/bin/bash

# Fail on any error.
set -e

# Display commands
set -x

# load necessary function definitions
. ${BUILD_DIR}/scripts/util_lib.sh

setEnvironmentVariables loadtest-env

pushDockerImages $ADAPTER_IMAGE_TAG

sed -i -e "s/google\/apigee-envoy-adapter:test/gcr.io\/${PROJECT}\/apigee-envoy-adapter:${ADAPTER_IMAGE_TAG}/g" ${REPO}/loadtest/k8s-files/apigee-envoy-adapter.yaml

kubectl apply -f ${REPO}/loadtest/k8s-files/apigee-envoy-adapter.yaml
sleep 20
kubectl apply -f ${REPO}/loadtest/k8s-files/locust-job.yaml
kubectl apply -f ${REPO}/loadtest/k8s-files/locust-worker.yaml

echo "Load/perf test is running. Wait for 25 minutes..."
sleep 1500

LOCUST=$(kubectl get pods -n apigee --selector=app=locust-manager -o json | jq -r ".items[0].metadata.name")
kubectl exec -n apigee $LOCUST -- sed -n "2p" adapter-load-test_stats.csv > stats.csv
while IFS=, read -r dummy1 dummy2 total failure median avg dummy3
do
    echo "total | failure | median (ms) | avgerage (ms)"
    echo "$total | $failure | $median | $avg"
    CODE=$(python -c "print(10 if float($failure)/$total > $LOADTEST_FAILURE_RATE or $avg > $LOADTEST_AVG_MAX else 0)")
done < stats.csv

kubectl delete -f ${REPO}/loadtest/k8s-files/apigee-envoy-adapter.yaml
kubectl delete -f ${REPO}/loadtest/k8s-files/locust-job.yaml
kubectl delete -f ${REPO}/loadtest/k8s-files/locust-worker.yaml

echo "Load/perf test is done."

exit $CODE




