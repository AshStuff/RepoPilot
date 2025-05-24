#!/bin/bash

# Script to build the base Docker image

set -e

DOCKER_IMAGE_NAME="repopilot/base"
DOCKER_IMAGE_TAG="latest"

echo "Building base Docker image: $DOCKER_IMAGE_NAME:$DOCKER_IMAGE_TAG"

# Build the Docker image using sudo
sudo docker build -t "$DOCKER_IMAGE_NAME:$DOCKER_IMAGE_TAG" -f Dockerfile.base .

echo "Base Docker image built successfully: $DOCKER_IMAGE_NAME:$DOCKER_IMAGE_TAG" 