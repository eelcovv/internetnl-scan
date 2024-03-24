==================
internetnl_scan
==================


A tool to control the scans at Internet.nl


Description
===========

This utility can be used to submit and access your internet.nl scans

Installation
============

Install the tool by::

    pip install internetnl-scan

In case you are behind a proxy which requires authentication you may want to install the packages
*requests_kerberos_proxy*. You can install it yourself with::

    pip install requests-kerberos-proxy

or, alternatively, install the nutstools package as::

    pip install internetnl-scan[proxy]

which will automatically include the required proxy packages

Note
====

This project has been set up using PyScaffold 3.2.3. For details and usage
information on PyScaffold see https://pyscaffold.org/.
