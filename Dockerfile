FROM ubuntu:latest
LABEL authors="siver"

ENTRYPOINT ["top", "-b"]