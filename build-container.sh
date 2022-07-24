#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

DOCKER_PROCESSES=$(pgrep docker)
if [ "${DOCKER_PROCESSES}" == "" ]
then :
  echo "Please ensure that docker is running"
  exit
fi

echo "Deleting any existing docker container..."
sudo docker rm -f connect3r_ssh

echo "Constructing docker container"
sudo docker build -t tagged_connect3r_ssh .
docker run -d -P -p 49158:22 --name connect3r_ssh tagged_connect3r_ssh

IP=$(sudo docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' connect3r_ssh)
echo "Test SSH Server given ip: ${IP}"

PORTS=$(sudo docker port connect3r_ssh)
echo "Test SSH Server exposed on ports:"
echo "${PORTS}"

echo "Exporting environment variables to .env file"
USERNAME="ssh_user"
PASSWORD="password"
printf "DOCKER_IP=%s\nDOCKER_USERNAME=%s\nDOCKER_PASSWORD=%s\nDOCKER_PORT=49158" "${IP}" "${USERNAME}" "${PASSWORD}" > .env