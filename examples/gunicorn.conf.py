import multiprocessing
import certifi

bind = '127.0.0.1:5000'
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'icebreakerone.trust.gunicorn.CustomSyncWorker'
timeout = 30
# Use certifi.where so we use the certifi CA store when handling SSL certs
ca_certs = certifi.where()
certfile = '/home/tom/Desktop/certs/127.0.0.1/cert.pem'
keyfile = '/home/tom/Desktop/certs/127.0.0.1/key.pem'
cert_reqs = 2
do_handshake_on_connect = True
