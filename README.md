# Microspace
Microspace is a lightweight container orchestration tool designed to replicate Docker functionalities for manual container creation with namespaces and groups. It provides developers with a simple yet powerful alternative to Docker, enabling them to deploy microservices efficiently in isolated environments.

## Key Features
- <b>Namespace Isolation</b>: Microspace leverages Linux namespaces to provide process isolation, filesystem isolation, network isolation, and more.
- <b>Control Groups (cgroups)</b>: The tool allows users to manage resource allocation and usage for processes within containers using control groups.
- <b>Network Configuration</b>: Users can configure network settings for containers, including IP addresses, port forwarding, and peer networking.
- <b>Manual Container Creation</b>: Microspace provides a command-line interface for manually creating and managing containers, giving users full control over the container environment.
- <b>Microservices Deployment</b>: With Microspace, developers can deploy microservices in isolated containers, facilitating modular and scalable application architectures.
- <b>Lightweight and Efficient</b>: Microspace is designed to be lightweight and efficient, providing essential container orchestration functionalities without the overhead of a full-fledged containerization platform like Docker.
