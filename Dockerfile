FROM python
ENV port 8000
ENV server_timeout 30
ENV server_workers 3
ENV MONGODB_HOST localhost
ENV MONGODB_PORT 27017
COPY . /digital-relay/
WORKDIR /digital-relay
RUN pip install -r requirements.txt
RUN pip install gunicorn
EXPOSE ${port}
CMD gunicorn -w ${server_workers} --timeout ${server_timeout} --reload --bind=0.0.0.0:${port} digital_relay_server:app
