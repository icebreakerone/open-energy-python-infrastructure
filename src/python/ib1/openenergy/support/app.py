import logging

from flask import Flask, request

import ib1.openenergy.support

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)

LOG = logging.getLogger('ib1.oe.testapp')


@app.route('/')
def homepage():
    LOG.info(f'peer certificate is {request.environ["peercert"]}')
    return '<html><body><h1>Success</h1></body></html>'


def run_simple_app():
    ib1.openenergy.support.run_app(app=app)
