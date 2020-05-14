[![<CirclCI>](https://circleci.com/gh/apigee/apigee-remote-service-envoy.svg?style=svg)](https://circleci.com/gh/apigee/apigee-remote-service-envoy)
[![Go Report Card](https://goreportcard.com/badge/github.com/apigee/apigee-remote-service-envoy)](https://goreportcard.com/report/github.com/apigee/apigee-remote-service-envoy)
[![codecov.io](https://codecov.io/github/apigee/apigee-remote-service-envoy/coverage.svg?branch=master)](https://codecov.io/github/apigee/apigee-remote-service-envoy?branch=master)

# Apigee Remote Service for Envoy

This project exposes standard Envoy gRPC endpoints for the `External Authorization (ext-authz)` 
and `gRPC Access Log Service (ALS)` interfaces. Thus, it allows Envoy to be used as a limited 
remote API Gateway extension to an Apigee environment. Features directly supported include: 
authentication and authorization via API Key or JWT OAuth Tokens, Distributed Quota, and Analytics.

Health check and prometheus management endpoints are also exposed.

See [releases](https://github.com/apigee/apigee-remote-service-envoy/releases) for current binary and docker images.

## Prerequisite: Apigee Runtime with remote-service proxy

An [Apigee account](https://cloud.google.com/apigee) is required to use this software.
[A free trial](https://login.apigee.com/sign__up) is available.

You must provision the `remote-service` proxy into your Apigee Runtime environment. 
This proxy exposes a runtime API that this project uses via a dependent library 
[apigee-remote-service-golib](https://github.com/apigee/apigee-remote-service-golib).

To get started, follow the [instructions](../../../apigee-remote-service-cli) to 
install the CLI and provision the proxy for your specific Apigee environment. You may
provision on any of the Apigee platforms (SaaS, Hybrid, or OPDK).

Be sure to save the configuration emitted from your provisioning as `config.yaml`. 
You'll need it to configure your Apigee Remote Service in the following steps.

## Getting Started

There are many ways to configure and use this software, but the following 
examples should help you get started:

### Istio Sidecar with Apigee Hybrid

[Getting Started with Hybrid](docs/demo-hybrid.md)

### Native Envoy with Apigee SaaS

[Getting Started with SaaS](docs/demo-native.md)

## Support

Issues filed on Github are not subject to service level agreements (SLAs) and responses should be
assumed to be on an ad-hoc volunteer basis. The [Apigee community board](https://community.apigee.com/) 
is recommended as for community support and is regularly checked by Apigee experts.

Apigee customers should use [formal support channels](https://cloud.google.com/apigee/support).
