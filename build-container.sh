#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

sudo docker compose down --volumes
sudo docker rm -f connect3r_ssh

sudo docker compose up

sudo docker build -t tagged_connect3r_ssh .
docker run -d -P --name connect3r_ssh tagged_connect3r_ssh

IP=$(sudo docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' connect3r_ssh)
echo "Test SSH Server given ip: ${IP}"

PORTS=$(sudo docker port connect3r_ssh)
echo "Test SSH Server exposed on ports:"
echo "${PORTS}"