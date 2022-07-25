
if (Get-PSSession)
{
    echo.
    echo You must right click to "Run as administrator"
    echo Try again
    echo ""
    pause
    goto : EOF
}

$string = $(Get-Process 'com.docker.proxy')
if ($string -contains "Get-Process : Cannot find a process with the name"){
    echo "Docker Daemon not running. Starting..."
    start-process "C:\Program Files\Docker\Docker\resources\com.docker.proxy"
}

#if (!$?) {
#    echo "Docker Daemon not running. Starting..."
#    start-process "C:\Program Files\Docker\Docker\resources\com.docker.proxy"
#}

echo "Deleting any existing docker container..."
docker rm -f connect3r_ssh
docker rmi -f tagged_connect3r_ssh

echo "Constructing docker container"
docker build -t tagged_connect3r_ssh .
docker run -d -P -p 12345:22 --name connect3r_ssh tagged_connect3r_ssh

IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' connect3r_ssh)
echo "Test SSH Server given ip: ${IP}"

PORTS=$(docker port connect3r_ssh)
echo "Test SSH Server exposed on ports:"
echo "${PORTS}"

echo "Exporting environment variables to .env file"
USERNAME="ssh_user"
PASSWORD="password"
printf "DOCKER_IP=%s\nDOCKER_USERNAME=%s\nDOCKER_PASSWORD=%s\nDOCKER_PORT=12345" "${IP}" "${USERNAME}" "${PASSWORD}" > .env