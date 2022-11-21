FROM python:3.8
ADD . /lookus
WORKDIR /lookus
RUN apt-get update && apt-get install -y python3 python3-pip net-tools iputils-ping nmap whatweb wkhtmltopdf
RUN python3 -m pip install -r requirements.txt
