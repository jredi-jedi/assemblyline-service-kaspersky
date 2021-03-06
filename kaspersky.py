from typing import Optional, Dict

from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.icap import IcapClient


class KasperskyIcapClient(IcapClient):
    """
    Kaspersky flavoured ICAP Client.

    Implemented against Kaspersky Scan Engine
    """

    def __init__(self, host: str, port: int, respmod_service: str) -> None:
        super(KasperskyIcapClient, self).__init__(host, port, respmod_service)

    def get_kaspersky_version(self) -> str:
        version = 'unknown'
        options_result = self.options_respmod()
        for line in options_result.splitlines():
            if line.startswith('Server:'):
                version = line[line.index(':')+1:].strip()
                break
        return version


class Kaspersky(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(Kaspersky, self).__init__(config)
        self.icap_host: str = ""
        self.icap_port: int = 0
        self.respmod_endpoint: str = ""
        self.icap: Optional[KasperskyIcapClient] = None

    def start(self) -> None:
        self.icap_host = self.config['icap_host']
        self.icap_port = int(self.config['icap_port'])
        self.respmod_endpoint = self.config["respmod_endpoint"]
        self.icap = KasperskyIcapClient(self.icap_host, self.icap_port, self.respmod_endpoint)

    def execute(self, request: ServiceRequest) -> None:
        request.result = Result()
        icap_result = self.icap.scan_data(request.file_contents, request.file_name)

        # if deepscan request include the ICAP HTTP and service version.
        if request.task.deep_scan:
            self._add_debug_information(request.result, icap_result)

        self._icap_to_alresult(request.result, icap_result)

    @staticmethod
    def _icap_to_alresult(result: Result, icap_result: str) -> None:
        virus_name = None
        result_lines = icap_result.strip().splitlines()
        if len(result_lines) <= 3:
            raise Exception('Invalid result from Kaspersky ICAP server: %s' % str(icap_result))

        xvirus_key = 'X-Virus-ID:'
        for line in result_lines:
            if line.startswith(xvirus_key):
                virus_name = line[len(xvirus_key):].strip()
                break

        # TODO: Isolate parts of X-Virus-ID according https://encyclopedia.kaspersky.com/knowledge/rules-for-naming/
        # So that we can tag more items of interest

        if virus_name and "HEUR:" in virus_name:
            virus_name = virus_name.replace("HEUR:", "")
            virus_heur_section = ResultSection(virus_name)
            virus_heur_section.set_heuristic(2)
            virus_heur_section.add_tag("av.heuristic", virus_name)
            result.add_section(virus_heur_section)
        elif virus_name:
            virus_hit_section = ResultSection(virus_name)
            virus_hit_section.set_heuristic(1)
            virus_hit_section.add_tag("av.virus_name", virus_name)
            result.add_section(virus_hit_section)

    def _add_debug_information(self, result: Result, icap_result: str) -> None:
        scan_engine_version = self.icap.get_kaspersky_version()
        scan_engine_version_section = ResultSection("Kaspersky Scan Engine Version", body=scan_engine_version)
        debug_info_section = ResultSection("ICAP HTTP Response", body=icap_result)
        result.add_section(scan_engine_version_section)
        result.add_section(debug_info_section)
