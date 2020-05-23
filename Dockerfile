FROM python
ENV port 8000
ENV server_timeout 30
ENV server_workers 3
ENV MONGODB_HOST localhost
ENV MONGODB_PORT 27017
ENV APP_URL http://localhost:4200
ENV MAIL_SERVER = localhost
ENV MAIL_PORT = 25
COPY . /digital-relay/
WORKDIR /digital-relay
RUN pip install -r requirements.txt
RUN pip install gunicorn
RUN wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | apt-key add -
RUN echo "deb http://repo.mongodb.org/apt/debian buster/mongodb-org/4.2 main" | tee /etc/apt/sources.list.d/mongodb-org-4.2.list
RUN apt-get update
RUN apt-get install -y mongodb-org
RUN mkdir -p /data/db
EXPOSE ${port}
CMD mongod | gunicorn -w ${server_workers} --timeout ${server_timeout} --reload --bind=0.0.0.0:${port} digital_relay_server:app
