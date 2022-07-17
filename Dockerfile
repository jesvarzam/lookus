FROM ubuntu:latest
COPY devicedetection/ /home/ubuntu
COPY requirements.txt /home/ubuntu
RUN apt-get update && apt-get install -y python3 python3-pip net-tools iputils-ping
RUN python3 -m pip install -r /home/ubuntu/requirements.txt
RUN python3 /home/ubuntu/manage.py makemigrations && python3 /home/ubuntu/manage.py migrate && python3 /home/ubuntu/manage.py runserver