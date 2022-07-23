# Connect3r
Connect3r is a a python package that will allow for quick, simple, and effective SSH connections
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
        Exporting environment variables
        ```
2. To initiate an SSH connection with the docker container, run:
   1. 
      ```commandline
      ssh ssh_user@<IP OF DOCKER CONTAINER>
      ```
   2. Accept the host key
   3. When prompted for the password, enter "password"

- If you want to change the username and/or password of the docker container:
  - Change ```RUN useradd -p $(openssl passwd -1 password) ssh_user``` in Dockerfile to:
    - ```RUN useradd -p $(openssl passwd -1 <password>) <username>```
  - Also, change the lines corresponding to username and password in build-container.sh so that unitests work:
    - ```
      USERNAME="<username>"
      PASSWORD="<password>"
      ```
  - When sshing into the container, make sure to update the username and ip in your command:
      - ```ssh <username>@<ip>```
