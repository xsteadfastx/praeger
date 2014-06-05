PRAEGER
=======

a flask based football betting app. named after the the VfL Wolfsburg Legend [Roy Präger](https://de.wikipedia.org/wiki/Roy_Pr%C3%A4ger).

## Running PRAEGER with Docker
1. Create MongoDB directory with `sudo mkdir /var/mongodb`
2. Build the image with `sudo docker.io build -t praeger .`
3. Run everything with `bash run.sh`
4. Configure NGINX to reverse proxy to 127.0.0.1:8000
5. You can ssh to the container with `ssh root@localhost -p2323`. The default password is "praeger"
