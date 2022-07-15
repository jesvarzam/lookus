FROM ubuntu:latest
COPY core/ /home/ubuntu
RUN apt-get update && apt-get install -y python3 python3-pip net-tools iputils-ping
RUN python3 -m pip install -r /home/ubuntu/requirements.txt
