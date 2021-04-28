""" Kaspersky AntiVirus Scanning Service.

    This service interfaces with Kaspersky AntiVirus for Proxy via ICAP.

    If was tested against:
        Kaspersky Antivirus for Proxy v5.5

    Dependencies:
       You must have a Kaspersky AV for Proxy running on the local network.

"""
from typing import Optional, Dict
from assemblyline_v4_service.common.result import Result, ResultSection
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common import icap


class KasperskyIcapClient(icap.IcapClient):
    """
    Kaspersky flavoured ICAP Client.

    Implemented against Kaspersky Anti-Virus for Proxy 5.5.
    """

    def __init__(self, host, port, respmod_service):
        super(KasperskyIcapClient, self).__init__(host, port, respmod_service)

    def get_kaspersky_version(self):
        version = 'unknown'
        options_result = self.options_respmod()
        for line in options_result.splitlines():
            if line.startswith('Server:'):
                version = line[line.index(':')+1:].strip()
                break
        return version


class KasperskyIcap(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(KasperskyIcap, self).__init__(config)
        self.icap_host = None
        self.icap_port = None
        self.kaspersy_version = None
        self.icap = None
        # self._av_info = ''

    def execute(self, request):
        service_version = self.icap.get_kaspersky_version()
        icap_result = self.icap.scan_data(request.file_contents, request.file_name)
        request.result = self.icap_to_alresult(icap_result)
        # request.task.report_service_context(self._av_info)

        # if deepscan request include the ICAP HTTP in debug info.
        # if request.task.deep_scan and request.task.profile:
        #     request.task.set_debug_info(icap_result)

    # def get_kaspersky_version(self):
    #     av_info = 'Kaspersky Antivirus for Proxy 5.5'
    #     defs = self.result_store.get_blob("kaspersky_update_definition")
    #     if defs:
    #         return "%s - Defs %s" % (av_info, defs.replace(".zip", "").replace("Updates", ""))
    #     return av_info

    # def get_tool_version(self):
    #     return self._av_info

    def icap_to_alresult(self, icap_result):
        x_response_info = None
        x_virus_id = None
        result_lines = icap_result.strip().splitlines()
        if not len(result_lines) > 3:
            raise Exception('Invalid result from Kaspersky ICAP server: %s' % str(icap_result))

        xri_key = 'X-Response-Info:'
        xvirus_key = 'X-Virus-ID:'
        for line in result_lines:
            if line.startswith(xri_key):
                x_response_info = line[len(xri_key):].strip()
            elif line.startswith(xvirus_key):
                x_virus_id = line[len(xvirus_key):].strip()

        result = Result()
        # Virus hits should have XRI of 'blocked' and XVIRUS containing the virus information.
        # Virus misses should have XRI of 'passed' and no XVIRUS section
        if x_virus_id:
            if not x_response_info == 'blocked':
                self.log.warn('found virus id but response was: %s', str(x_response_info))
            virus_name = x_virus_id.replace('INFECTED ', '')
            virus_hit_section = ResultSection(virus_name)
            virus_hit_section.set_heuristic(1)
            virus_hit_section.add_tag("av.virus_name", virus_name)
            result.add_section(virus_hit_section)
        return result

    def start(self):
        self.icap_host = self.config.get('icap_host')
        self.icap_port = int(self.config.get('icap_port'))
        self.respmod_endpoint = self.config.get("respmod_endpoint")
        self.icap = KasperskyIcapClient(self.icap_host, self.icap_port, self.respmod_endpoint)
        # self._av_info = self.get_kaspersky_version()
