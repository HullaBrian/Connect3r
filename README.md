# Connect3r
Connect3r is a a python package that aims to allow for quick, simple, and effective SSH connections using as much vanilla python as possible.

**Note**: Connect3r is not technically released yet. It is under development still, so there is no guarantee that it will work if you use it.

I'm currently looking at using a 3rd party [openSSH implementation](https://github.com/openssh/openssh-portable) or [libSSH](https://api.libssh.org/stable/libssh_tutor_shell.html#opening_shell) then using those C functions in the library to do the heavy lifting for me. Below is a link to using C functions in Python:

https://www.geeksforgeeks.org/how-to-call-a-c-function-in-python/
# Setup for Docker Container
To setup the docker container used for testing purposes:
1. Run "build-container.sh" with super-user privileges:
   1. ``sudo ./build-container.sh`` **YOU NEED SUPER-USER PRIVILEGES**
   2. Be sure to take note of the ip and ports listed in the output:
        ```
        Test SSH Server given ip: 172.17.0.2
        Test SSH Server exposed on ports:
        22/tcp -> 0.0.0.0:12345
        22/tcp -> :::12345
        Exporting environment variables
        ```
2. To initiate an SSH connection with the docker container, run:
      ```
      ssh ssh_user@<IP OF DOCKER CONTAINER>
      ```
   - Accept the host key
   - When prompted for the password, enter "password"

### Changing the default username, password, and/or port number of container
- By default, the variables used by the docker container are:
  - username: "ssh_user"
  - password: "password"
  - port: "12345"
- Username and/or password:
  - Change ```RUN useradd -p $(openssl passwd -1 password) ssh_user``` in Dockerfile to ```RUN useradd -p $(openssl passwd -1 <password>) <username>``` 
  - Also, change the lines corresponding to username and password in "*build-container.sh*" so that unitests work:
    - ```
      USERNAME="<username>"
      PASSWORD="<password>"
      ```
  - When sshing into the container, make sure to update the username and ip in your command:
      - ```ssh <username>@<ip>```
- Port number:
  - In "*build-container.sh*", go to ```printf "DOCKER_IP=%s\nDOCKER_USERNAME=%s\nDOCKER_PASSWORD=%s\nDOCKER_PORT=49158" "${IP}" "${USERNAME}" "${PASSWORD}" > .env```, and change the DOCKER_PORT to your desired port number
  - Also, in "*build-container.sh*", go to ```docker run -d -P -p 12345:22 --name connect3r_ssh tagged_connect3r_ssh```, and change the 12345 to your desired port
