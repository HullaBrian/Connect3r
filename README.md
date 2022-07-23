# Connect3r

# Setup
To setup the docker container used for testing purposes:
1. Run "build-container.sh" as the root user:
   1. ``sudo ./build-container.sh``
   2. Be sure to take note of the ip and ports listed in the output:
        ```
        Test SSH Server given ip: 172.17.0.2
        Test SSH Server exposed on ports:
        22/tcp -> 0.0.0.0:49161
        22/tcp -> :::49161
        ```
2. To initiate an SSH connection with the docker container, run:
   1. 
      ```commandline
      ssh ssh_user@<IP OF DOCKER CONTAINER>
      ```
   2. Accept the host key
   3. When prompted for the password, enter "password"