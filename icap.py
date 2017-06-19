#!/usr/bin/env python

import base64
import os
import socket
import errno

from cStringIO import StringIO

ICAP_OK = 'ICAP/1.0 200 OK'

class IcapClient(object):
    """
    A limited Internet Content Adaptation Protocol client.

    Currently only supports RESPMOD as that is all that is required to interop
    with most ICAP based AV servers.
    """

    def __init__(self, host, port, respmod_service):
        self.host = host
        self.port = port
        self.service = respmod_service

    def scan_data(self, data, name=None):
        return self._do_respmod(name or 'filetoscan', data)

    def scan_local_file(self, filepath):
        filename = os.path.basename(filepath)
        with open(filepath, 'r') as f:
            data = f.read()
            return self.scan_data(data, filename)

    def options_respmod(self):
        s = socket.create_connection((self.host, self.port))
        s.sendall("OPTIONS icap://{HOST}/{SERVICE} ICAP/1.0\r\n\r\n".format(
            HOST=self.host, SERVICE=self.service))
        response = s.recv(65565)
        if not response or not response.startswith(ICAP_OK):
            raise Exception("Unexpected OPTIONS response: %s", response)
        return response


    def _do_respmod(self, filename, data):
        encoded = base64.encodestring(data)
        encoded_len = format(len(encoded), 'X')

        # ICAP RESPMOD req-hdr is the start of the original HTTP request.
        respmod_req_hdr = "GET /{FILENAME} HTTP/1.1\r\n\r\n".format(FILENAME=filename)

        # ICAP RESPMOD res-hdr is the start of the HTTP response for above request.
        respmod_res_hdr = (
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n\r\n")

        res_hdr_offset = len(respmod_req_hdr)
        res_bdy_offset = len(respmod_res_hdr) + res_hdr_offset

        # The ICAP RESPMOD header. Note:
        # res-hdr offset should match the start of the GET request above.
        # res-body offset should match the start of the response above.

        respmod_icap_hdr = (
            "RESPMOD icap://{HOST}:{PORT}/{SERVICE} ICAP/1.0\r\n"
            "Host:{HOST}:{PORT}\r\n"
            "Allow:204\r\n"
            "Encapsulated: req-hdr=0, res-hdr={RES_HDR}, res-body={RES_BODY}\r\n\r\n"
        ).format(HOST=self.host, PORT=self.port, SERVICE=self.service, 
                 RES_HDR=res_hdr_offset, RES_BODY=res_bdy_offset)

        sio = StringIO()
        sio.write(respmod_icap_hdr)
        sio.write(respmod_req_hdr)
        sio.write(respmod_res_hdr)
        sio.write(encoded_len + "\r\n")
        sio.write(encoded)
        sio.write('\r\n0\r\n\r\n')   # terminate with 0 length chunk
        serialized_request = sio.getvalue()

        _e = None
        for i in xrange(3):
            try:
                s = socket.create_connection((self.host, self.port), timeout=10)
                s.sendall(serialized_request)
                response = ""
                while True:
                    try:
                        r_2 = s.recv(65565)
                        response += r_2
                        if r_2 == "" or "\r\n\r\n" in response:
                            break
                    except socket.error as ret_code:
                        if ret_code.errno in [errno.ECONNRESET, errno.ECONNABORTED]:
                            break
                        raise
                s.close()
                if response != "":
                    return response
            except socket.error as e:
                _e = e
                continue

        if _e is not None:
            raise _e

        raise Exception("Icap server refused to respond.")


class KasperskyIcapClient(IcapClient):
    """ 
    Kaspersky flavoured ICAP Client.

    Implemented against Kaspersky Anti-Virus for Proxy 5.5.
    """

    def __init__(self, host, port):
        super(KasperskyIcapClient, self).__init__(
            host, port, respmod_service='av/respmod')

    def get_service_version(self):
        version = 'unknown'
        options_result = self.options_respmod()
        for line in options_result.splitlines():
            if line.startswith('Service:'):
                version = line[line.index(':')+1:].strip()
                break
        return version

class SymantecIcapClient(IcapClient):
    """
    Symantec flavoured ICAP Client.

    Implemented against Symantec Protection Engine for Cloud Services.

    INCOMPLETE 
    """
    def __init__(self, host, port):
         super(SymantecIcapClient, self).__init__(
             host, port, respmod_service='SYMScanRespEx')

    def get_service_version(self):
        engine_version = 'unknown'
        definition_version = 'unknown' 
        options_result = self.options_respmod()
        for line in options_result.splitlines():
            if line.startswith('Service:'):
                engine_version = line[line.index(':')+1:].strip()
            elif line.startswith('X-Definition-Info'):
                definition_version = line[line.index(':')+1:].strip()
        return '{engine:{}, definitions:{}'.format(engine_version, definition_version)


if __name__ == '__main__':
    icap_host = "192.168.122.99"
    client = KasperskyIcapClient(icap_host, 1344)
    print client.options_respmod()
    print client.get_service_version()
    print client.scan_local_file('./testfile')
