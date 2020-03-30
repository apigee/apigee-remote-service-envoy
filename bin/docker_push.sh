#!/bin/bash

# This script will construct a Docker image and push it to GCR.
#
# Prereqs:
# - docker is installed.
# - gcloud is installed.
#
# Variables:
# - GCLOUD_SERVICE_KEY - auth key for the service account (used in CI to build nightly)
# - GCP_PROJECT - which GCP_PROJECT to upload the image to.
# - TARGET_DOCKER_IMAGE - the name of the docker image to build.
# - DEBUG - set DEBUG=1 to also build and push a debug image.
# - TARGET_DOCKER_DEBUG_IMAGE - the name of the docker debug image to build.

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOTDIR="$(dirname "$SCRIPTPATH")"

echo "Checking environment settings..."

if [[ $GCLOUD_SERVICE_KEY == "" ]]; then
  echo "GCLOUD_SERVICE_KEY not set, not using service account."
fi

if [[ $GCP_PROJECT == "" ]]; then
  echo "GCP_PROJECT not set, please set it."
  exit 1
fi

if [[ "${TARGET_DOCKER_IMAGE}" == "" ]]; then
  TARGET_DOCKER_IMAGE="gcr.io/${GCP_PROJECT}/apigee-remote-service-envoy"
  echo "TARGET_DOCKER_IMAGE not set, defaulting to ${TARGET_DOCKER_IMAGE}."
fi

if [[ "${DEBUG}" == "1" && "${TARGET_DOCKER_DEBUG_IMAGE}" == "" ]]; then
  TARGET_DOCKER_DEBUG_IMAGE="gcr.io/${GCP_PROJECT}/apigee-remote-service-envoy-debug"
  echo "TARGET_DOCKER_DEBUG_IMAGE not set, defaulting to ${TARGET_DOCKER_DEBUG_IMAGE}."
fi

if [[ `command -v docker` == "" ]]; then
  echo "docker client not installed, please install it: ./bin/install_docker.sh"
  exit 1
fi

if [[ `command -v gcloud` == "" ]]; then
  echo "gcloud not installed, please install it: ./bin/install_gcloud.sh"
  exit 1
fi

gcloud --quiet components update
gcloud config set project "${GCP_PROJECT}" || exit 1

if [[ $GCLOUD_SERVICE_KEY != "" ]]; then
  echo "Authenticating service account with GCP..."
  echo $GCLOUD_SERVICE_KEY | base64 --decode --ignore-garbage > ${HOME}/gcloud-service-key.json

  export GOOGLE_APPLICATION_CREDENTIALS=${HOME}/gcloud-service-key.json
  gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS || exit 1

  echo "Need sudo to install docker-credential-gcr, requesting password..."
  sudo gcloud components install docker-credential-gcr || exit 1

  if [[ `command -v docker-credential-gcr` == "" ]]; then
    # It should be installed, so check if it is in the temp dir.
    if [ -d /opt/google-cloud-sdk/bin ]; then
      export PATH=$PATH:/opt/google-cloud-sdk/bin
    else
      echo "Not able to find docker-credential-gcr, you may need to add the GCP SDK to your PATH."
      exit 1
    fi
  fi

  docker-credential-gcr configure-docker || exit 1

  docker login -u _json_key -p "$(cat ${HOME}/gcloud-service-key.json)" https://gcr.io || exit 1
fi

echo "Building docker image..."

cd "${ROOTDIR}"
docker build -t apigee-remote-service-envoy -f Dockerfile .

IMAGE_ID=$(docker images apigee-remote-service-envoy --format "{{.ID}}" | head -n1)

if [[ "${IMAGE_ID}" == "" ]]; then
  echo "No image found for apigee-remote-service-envoy. Does it exist?"
  exit 1
fi

docker tag "${IMAGE_ID}" "${TARGET_DOCKER_IMAGE}" || exit 1
echo "Pushing ${TARGET_DOCKER_IMAGE}..."
gcloud auth configure-docker --quiet
docker push "${TARGET_DOCKER_IMAGE}" || exit 1

if [[ "${DEBUG}" == "1" ]]; then
  docker build -t apigee-remote-service-envoy-debug -f Dockerfile_debug .

  IMAGE_ID=$(docker images apigee-remote-service-envoy-debug --format "{{.ID}}" | head -n1)

  if [[ "${IMAGE_ID}" == "" ]]; then
    echo "No image found for apigee-remote-service-envoy-debug. Does it exist?"
    exit 1
  fi

  docker tag "${IMAGE_ID}" "${TARGET_DOCKER_DEBUG_IMAGE}" || exit 1
  echo "Pushing ${TARGET_DOCKER_DEBUG_IMAGE}..."
  docker push "${TARGET_DOCKER_DEBUG_IMAGE}" || exit 1
fi

if [[ "${MAKE_PUBLIC}" == "1" ]]; then
  gsutil iam ch allUsers:objectViewer "gs://artifacts.${GCP_PROJECT}.appspot.com/"
fi
