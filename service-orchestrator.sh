#!/bin/bash

# Complete this script to deploy external-service and counter-service in two separate containers
# You will be using the conductor tool that you completed in task 3.

# Creating link to the tool within this directory
ln -s ../task3/conductor.sh conductor.sh
ln -s ../task3/config.sh config.sh

# use the above scripts to accomplish the following actions -

# Logical actions to do:
# 1. Build image for the container
./conductor.sh build mydebian

# 2. Run two containers say c1 and c2 which should run in background. Tip: to keep the container running
#    in background you should use a init program that will not interact with the terminal and will not
#    exit. e.g. sleep infinity, tail -f /dev/null
./conductor.sh run mydebian c1 'tail -f /dev/null' &
./conductor.sh run mydebian c2 'tail -f /dev/null' &
sleep 5

# 3. Copy directory external-service to c1 and counter-service to c2 at appropriate location. You can
#    put these directories in the containers by copying them within ".containers/{c1,c2}/rootfs/" directory
cp -a external-service ./.containers/c1/rootfs
cp -a counter-service ./.containers/c2/rootfs

# chmod -R 755 counter-service
# chmod -R 755 external-service

# 4. Configure network such that:
#    4.a: c1 is connected to the internet and c1 has its port 8080 forwarded to port 3000 of the host
#    4.b: c2 is connected to the internet and does not have any port exposed
#    4.c: peer network is setup between c1 and c2
./conductor.sh -i -e 8080-3000 addnetwork c1
./conductor.sh -i addnetwork c2
./conductor.sh peer c1 c2

# 5. Get ip address of c2. You should use script to get the ip address. 
#    You can use ip interface configuration within the host to get ip address of c2 or you can 
#    exec any command within c2 to get it's ip address
output=$(sudo bash conductor.sh exec c2 "ip a")
ip=$(echo "$output" | grep c2-inside | grep inet | awk '{print $2}' | cut -d '/' -f1)

# 6. Within c2 launch the counter service using exec [path to counter-service directory within c2]/run.sh
sudo ./conductor.sh exec c2 "apt update" 
sudo ./conductor.sh exec c2 "apt install net-tools" 
sudo ./conductor.sh exec c2 "counter-service/run.sh" &
while true; do
    portNo=$(sudo ./conductor.sh exec c2 "netstat -tuln" | grep 8080)
    if [ -n "$portNo" ]; then
        echo "Port :: 8080 [LIVE]"
        break
    else
        echo "Port :: 8080 [NOT LIVE]"
        sleep 2
    fi
done

# 7. Within c1 launch the external service using exec [path to external-service directory within c1]/run.sh
./conductor.sh exec c1 "apt update" 
./conductor.sh exec c1 "apt install net-tools" 
./conductor.sh exec c1 "external-service/run.sh http://$ip:8080/" &
while true; do
    portNo=$(sudo ./conductor.sh exec c1 "netstat -tuln" | grep 8080)
    if [ -n "$portNo" ]; then
        echo "Port :: 8080 [LIVE]"
        break
    else
        echo "Port :: 8080 [NOT LIVE]"
        sleep 2
    fi
done

# 8. Within your host system open/curl the url: http://localhost:3000 to verify output of the service
# curl http://localhost:3000  

ip=$(ip a | grep enp | grep inet | awk '{print $2}' | cut -d '/' -f1)
curl http://$ip:3000 

# 9. On any system which can ping the host system open/curl the url: `http://<host-ip>:3000` to verify
#    output of the service

wait