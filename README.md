[![<CirclCI>](https://circleci.com/gh/apigee/apigee-remote-service-envoy.svg?style=svg)](https://circleci.com/gh/apigee/apigee-remote-service-envoy)
[![Go Report Card](https://goreportcard.com/badge/github.com/apigee/apigee-remote-service-envoy)](https://goreportcard.com/report/github.com/apigee/apigee-remote-service-envoy)
[![codecov.io](https://codecov.io/github/apigee/apigee-remote-service-envoy/coverage.svg?branch=master)](https://codecov.io/github/apigee/apigee-remote-service-envoy?branch=master)

# Apigee Remote Service for Envoy

Apigee integration for Envoy.

## Prerequisite: Apigee

You must have an [Apigee](https://cloud.google.com/apigee/) account. 
[Try it free](https://login.apigee.com/sign__up) if you don't!

## Getting Started

You must provision the `remote-service` proxy into your Apigee Runtime environment. 
This proxy provides a necessary API for the remote service to access Apigee data. 

Follow the [instructions](../../../apigee-remote-service-cli) to install the CLI and 
provision the proxy for your specific Apigee environment. You are able to provision 
on Apigee SaaS, Hybrid, or OPDK.

Be sure to save the configuration emitted from your provisioning as `config.yaml`! 
You'll need it to configure your Apigee Remote Service in the following steps.

## Next Steps

### Istio Sidecar with Apigee Hybrid

[Getting Started with Hybrid](docs/demo-hybrid.md)

### Native Envoy with Apigee SaaS

[Getting Started with SaaS](docs/demo-native.md)

## Support

Issues filed on Github are not subject to service level agreements (SLAs) and responses should be
assumed to be on an ad-hoc volunteer basis. The [Apigee community board](https://community.apigee.com/) 
is recommended as for community support and is regularly checked by Apigee experts.

Apigee customers should use [formal support channels](https://cloud.google.com/apigee/support).
