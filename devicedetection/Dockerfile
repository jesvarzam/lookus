FROM python:3.8-slim-buster
WORKDIR /lookus
COPY . .
RUN apt-get update && apt-get install -y python3 python3-pip net-tools iputils-ping nmap whatweb
RUN python3 -m pip install -r requirements.txt
CMD ["python3", "manage.py" , "runserver", "0.0.0.0:8000"]