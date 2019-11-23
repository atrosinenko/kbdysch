#!/bin/sh

cd $(dirname $0)/generator
java -jar sbt-launch.jar 'run fs.txt:invoker-fs.c'
