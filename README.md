# Kaspersky Service

This Assemblyline services interfaces with [Kaspersky Antivirus for Proxy Server](https://www.kaspersky.com/small-to-medium-business-security/proxy-server).

**NOTE**: This service **requires you to buy** any licence. It also **requires you to install** Kas4Proxy on a seperate machine/VM. It is **not** preinstalled during a default installation

## Execution

The service use our generic icap interface to send the file to the proxy server for analysis and report the results back to the user.

## Installation of Kas4Proxy

To install Kas4Proxy you can follow our detailled documentation [here](icap_installation/install_notes.md).

## Updates

This service support auto-update in both online and offline environment. This is configurable in the service config.

## Licensing

The service was developed with Kas4Proxy Linux Version: 5.5

Contact your Kaspersky reseller to get access to the proper licence you need for your deployment: [https://www.kaspersky.com/small-to-medium-business-security/how-to-buy](https://www.kaspersky.com/small-to-medium-business-security/how-to-buy)