#!/bin/sh
#
# Creates a htpasswd file and bootstraps a docker registry with user 'bollard'.
# Pulls all the images needed to run the integration suite and pushes them to
# the registry. Finally, runs the tests.

export REGISTRY_PASSWORD=$(date | md5sum | cut -f1 -d\ )
docker create -v /etc/docker/registry --name config alpine:3 /bin/true
echo -n "${REGISTRY_PASSWORD}" | docker run --rm -i --entrypoint=htpasswd --volumes-from config nimmis/alpine-apache -i -B -c /etc/docker/registry/htpasswd bollard
cat resources/dockerfiles/registry/config.yml | docker run --rm -i --volumes-from config --entrypoint=tee alpine:3 /etc/docker/registry/config.yml
docker run -d --restart always --name registry -p 5000:5000 --volumes-from config registry:2
sleep 4
docker login --username bollard --password "${REGISTRY_PASSWORD}" localhost:5000
docker pull hello-world:linux
docker pull fussybeaver/uhttpd
docker pull alpine
docker tag hello-world:linux localhost:5000/hello-world:linux
docker tag fussybeaver/uhttpd localhost:5000/fussybeaver/uhttpd
docker tag alpine localhost:5000/alpine
docker push localhost:5000/hello-world:linux
docker push localhost:5000/fussybeaver/uhttpd
docker push localhost:5000/alpine
docker swarm init
docker run -e RUST_LOG=bollard=trace -e REGISTRY_PASSWORD -e REGISTRY_HTTP_ADDR=localhost:5000 -v /var/run/docker.sock:/var/run/docker.sock $DOCKER_PARAMETERS -ti --rm bollard cargo test $@ -- --test-threads 1
