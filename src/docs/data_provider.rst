Building a Data Provider
========================

TODO - insert instructions here

A :term:`data provider` (|DP|) deploys an HTTP |API| secured by the `Financial Grade API`_ (FAPI) standard. We provide a
`flask` route decorator which will automatically perform the necessary token checks, injecting information about the
client into the `flask.g` global - you can then use this information to drive access control decisions.

The example below shows the simplest possible secure application. It configures an instance of
`AccessTokenValidator` with:

- a client certificate and private key which will be used to communicate with the authorization server
- client ID for this communication
- URL of the token introspection endpoint, this is used to validate a supplied bearer token

This is then used to decorate a simple flask route within the app.

.. literalinclude:: ../../examples/app.py
    :language: python
    :linenos:

.. _Financial Grade API: https://openid.net/wg/fapi/