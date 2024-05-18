#!/bin/bash

## You need to modify this as per your system, 
## This should be the interface of your system connecting 
## to internet. 
DEFAULT_IFC=enp0s3


# These are the configuration files that you may have to fill
IP4_SUBNET=192.168
IP4_PREFIX_SIZE=24 # Size of assigned prefixes
IP4_FULL_PREFIX_SIZE=16 # Size of IP4_SUBNET



# Don't modify below this line
NEEDED_TOOLS="ip ping iptables top debootstrap"
IMAGEDIR="$(dirname "$0")/.images"
CONTAINERDIR="$(dirname "$0")/.containers"
EXTRADIR="$(dirname "$0")/extras"
SETUP_SCRIPT="$(dirname "$0")/conductor.sh"
IP4_PREFIX=
PORT=
INNER_PORT=
OUTER_PORT=
INTERNET=0
EXPOSE=0