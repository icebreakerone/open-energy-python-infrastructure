# Certificate management

This repository contains helper utilities and classes to get a sample data provider or service provider up and running
as fast as possible. Some of the steps described here are not suitable for production use, in particular the use of
locally generated root CAs and certificates for `localhost` or similar.

## Development SSL certificate for your test provider

You can run a Flask app with HTTPS in development mode using the tools in this repository, but you'll need a valid
server certificate for it. I've used https://github.com/jsha/minica to generate a key pair for `127.0.0.1`, you'll also
need to add the generated `minica.pem` to the root CA list for both Python and (if you want to be able to use
e.g. `curl` to test) your system root CAs.

To add a root CA on ubuntu-like systems do the following - note that you have to rename `minica.pem` to `minica.crt` or
this will not work:

```shell
sudo cp minica.pem /usr/share/ca-certificates/minica.crt
sudo dpkg-reconfigure ca-certificates
```

You'll need to select the entry for `minica.crt`, then enter to update the configuration. This will allow system tools
like `curl` to access your provider without complaining.

See the section below for instructions to get the minica cert into your python trusted root CA list. This is what you
need to enable access from the client library in this repository.

## Raidiam sandbox certificate

This is the root and issuing certificate used by the current UAT sandbox to mint client certificates. It needs to be
installed into the `certifi` CA set. You can do this with e.g.

```python
import certifi

cafile = certifi.where()
with open('raidiam_certificate_chain.pem', 'rb') as infile:
    customca = infile.read()
with open(cafile, 'ab') as outfile:
    outfile.write(customca)
```

(or just use `cat raidiam_certificate_chain.pem >> EXISTING_CA_FILE` or similar from the command line if you have easy
access to the location of the certifi root CAs)

This is necessary for the provider to validate client certificates.