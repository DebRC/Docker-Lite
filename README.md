# Docker Lite - A Container Creation Tool
Microspace is a lightweight containerization tool designed to replicate Docker functionalities through manual container creation with namespaces and cgroups. It offers developers a straightforward yet powerful alternative to Docker, allowing efficient deployment and management of applications in isolated environments.

Note: <i>conductor.sh can create only Debian container images. Can be changed by replacing debootstrap with proper commands.</i>

## Comparison with Docker
![image](https://github.com/DebRC/Microspace/assets/63597606/8060cb54-72a7-4a00-b9b6-9f96070da3cc)

## Service Orchestrator
This example script deploys two separate web services, one internal and another external, on two separate containers, and then connect and expose the external service using the given functionalities.

### 1. **Linux System Programming**
- **System Calls**: Understanding and implementing Linux system calls like `clone`, `setns`, `unshare`, and `pidfd_open` is crucial. These calls are used to manipulate namespaces and create isolated environments for processes.
- **Namespaces**: Knowledge of different types of namespaces (PID, UTS, mount, network, etc.) and how to manage them using system calls.
- **Processes and PIDs**: Creating and managing processes, understanding PID namespaces, and ensuring correct process isolation.

### 2. **Containerization**
- **chroot**: Using `chroot` to change the root directory of a process, creating an isolated file system environment.
- **unshare**: Creating new namespaces for containers to isolate processes.
- **cgroups**: Managing control groups to limit resource usage, specifically CPU quotas.

### 3. **Shell Scripting**
- **Bash Scripting**: Writing and modifying bash scripts to automate tasks, configure environments, and manage container lifecycle.
- **Script Execution**: Handling script parameters and executing commands conditionally within scripts.

### 4. **Virtualization and Environment Setup**
- **Virtual Machines**: Setting up and using VirtualBox or UTM to create a consistent environment for development and testing.
- **VM Management**: Handling VM credentials, ensuring correct setup and configuration.

### 5. **Networking**
- **Network Namespaces**: Creating and managing network namespaces to isolate network resources.
- **veth Pairs**: Setting up virtual Ethernet devices to connect containers to host networks.
- **IP Configuration**: Configuring IP addresses and routes to enable communication between containers and the host.

### 6. **Tool Usage**
- **debootstrap**: Using `debootstrap` to create Debian-based container images.
- **iptables**: Configuring firewall rules and network address translation (NAT) to manage container networking.

### 7. **Container Management Tools**
- **Docker-like Functionality**: Implementing container management functions similar to Docker, such as `build`, `run`, `stop`, `exec`, `ps`, and network management.
- **File Systems**: Understanding and working with different file systems, and ensuring proper mounts inside containers.

### 8. **Debugging and Problem Solving**
- **Log Analysis**: Reviewing system and application logs to debug issues.
- **Troubleshooting**: Identifying and fixing issues related to process isolation, network configuration, and resource management.

### Detailed Breakdown of Tasks and Skills:

#### Task 1: Namespaces with System Calls
- Implement process creation and namespace management using system calls.
- Ensure two processes share the same PID and UTS namespace.

#### Task 2: CLI Containers
- **Subtask 2a**: Implement chroot-based filesystem isolation.
- **Subtask 2b**: Extend isolation by adding PID and UTS namespaces.
- **Subtask 2c**: Implement resource limitation using cgroups.

#### Task 3: Containers in the Wild
- **Subtask 3a**: Implement the `run` command to use `unshare` and `chroot` for container creation.
- **Subtask 3b**: Implement the `exec` command to run processes in existing containers.
- **Subtask 3c**: Implement container networking using veth pairs and ensure proper communication.

#### Task 4: Creating the Matrix
- Set up containers to run services and configure networking such that:
  - One container is accessible externally and can communicate with the other container internally.
  - Implement port forwarding and inter-container communication.
