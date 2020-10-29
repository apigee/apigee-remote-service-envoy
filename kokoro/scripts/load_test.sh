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

# load necessary function definitions
#. ${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-envoy/kokoro/scripts/lib.sh
. /usr/local/google/home/lwge/repos/apigee-remote-service-envoy/kokoro/scripts/lib.sh

setEnvironmentVariables loadtest-env

sed -i -e "s/google\/apigee-envoy-adapter/gcr.io\/${PROJECT}\/apigee-envoy-adapter/g" ${REPO}/loadtest/k8s-files/apigee-envoy-adapter.yaml

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
    CODE=$(python -c "print(10 if float($failure)/$total > 0.001 or $avg > 100 else 0)")
done < stats.csv

kubectl delete -f ${REPO}/loadtest/k8s-files/apigee-envoy-adapter.yaml
kubectl delete -f ${REPO}/loadtest/k8s-files/locust-job.yaml
kubectl delete -f ${REPO}/loadtest/k8s-files/locust-worker.yaml

echo "Load/perf test is done."

exit $CODE




