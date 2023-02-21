#!/bin/bash

docker-compose up --no-deps --build --detach mitm
sleep 7
docker-compose up --no-deps --build client

docker-compose stop mitm

docker-compose --ansi always logs client > mitm_output.txt
docker-compose --ansi always logs mitm | tee mitm_output.txt
