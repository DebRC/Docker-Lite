# Micro-Dock - Replica of Docker
Microspace is a lightweight container orchestration tool designed to replicate Docker functionalities for manual container creation with namespaces and cgroups. It provides developers with a simple yet powerful alternative to Docker, enabling them to deploy microservices efficiently in isolated environments.

Note: <i>conductor.sh can create only Debian container images. Can be changed by replacing debootstrap with proper commands.</i>

## Comparison with Docker
![image](https://github.com/DebRC/Microspace/assets/63597606/8060cb54-72a7-4a00-b9b6-9f96070da3cc)

## Service Orchestrator
This example script deploys two separate web services, one internal and another external, on two separate containers, and then connect and expose the external service using the given functionalities.
