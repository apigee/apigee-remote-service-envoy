---
name: New report
about: File an issue to help improve the product
title: 'Issue report'
labels: ''
assignees: ''

---

Issues filed on Github are not subject to service level agreements (SLAs) and responses 
should be assumed to be on an ad-hoc volunteer basis. The Apigee community board is 
recommended for community support and is regularly checked by Apigee experts. Apigee
customers should use formal support channels. 
See the `Get help!` page in the wiki for more information.

---
### Describe your issue
What are you seeing?
What were you expecting?
Which playbooks did you follow?
What were the results of that investigation?
What other investigative actions did you take?

### What's your environment?
What is your environment?
What version are you running?
What Apigee environment (eg. hybrid, SaaS, OPDK)?
What is your OS and version?
What version of Envoy?
If you're using Kubernetes and/or Istio - what are their versions?
Is there anything unique about your deployment?

### What's your Configuration?
What is your configuration for apigee-remote-service-envoy?
What is your configuration for envoy?
Be sure to exclude any sensitive information.

### Steps to Reproduce
Can your issue be recreated?
Will we be able to recreate your issue?
If so, how can we do recreate it?

### Additional context
Anything else you can tell us that might be helpful?

### Attach relevant logs
Attach relevant log files, preferably at debug level, and fitered as narrowly as possible
to only the lines dealing with the request where you are seeing the issue.
We'll likely at least need logs from `apigee-remote-service-envoy` and `envoy`.
