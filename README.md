# Kaspersky Service

This Assemblyline service interfaces with [Kaspersky Scan Engine in ICAP Mode](https://support.kaspersky.com/ScanEngine/1.0/en-US/184798.htm).

**NOTE**: This service **requires you to buy** a licence. It also **requires you to install** Kaspersky Scan Engine in ICAP Mode on a separate machine/VM. It is **not** preinstalled during a default installation

## Execution

The service uses our generic ICAP interface to send files to the proxy server for analysis and report the results back to the user.

## Installation of Kaspersky Scan Engine

To install Kaspersky Scan Engine in ICAP Mode you can follow our detailed documentation [here](icap_installation/install_notes.md).

## Updates

This service supports auto-update in both online and offline environments. This is configurable in the service config.

## Licensing

The service was developed with Kasperksy Scan Engine in ICAP Mode Linux Version: KL ICAP Service v1.0 (KAV SDK v8.9.2.595)

Contact your Kaspersky reseller to get access to the licence you need for your deployment: [https://www.kaspersky.com/scan-engine](https://www.kaspersky.com/scan-engine)