import os
import json
import pytest
import shutil

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
samples = [
    dict(
        sid=1,
        metadata={},
        service_name='kaspersky',
        service_config={},
        fileinfo=dict(
            magic='ASCII text, with no line terminators',
            md5='fda4e701258ba56f465e3636e60d36ec',
            mime='text/plain',
            sha1='af2c2618032c679333bebf745e75f9088748d737',
            sha256='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
            size=19,
            type='unknown',
        ),
        filename='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
        min_classification='TLP:WHITE',
        max_files=501,  # TODO: get the actual value
        ttl=3600,
    ),
]


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        heuristic_equality = this.heuristic.definition.attack_id == that.heuristic.definition.attack_id and \
                             this.heuristic.definition.classification == that.heuristic.definition.classification and \
                             this.heuristic.definition.description == that.heuristic.definition.description and \
                             this.heuristic.definition.filetype == that.heuristic.definition.filetype and \
                             this.heuristic.definition.heur_id == that.heuristic.definition.heur_id and \
                             this.heuristic.definition.id == that.heuristic.definition.id and \
                             this.heuristic.definition.max_score == that.heuristic.definition.max_score and \
                             this.heuristic.definition.name == that.heuristic.definition.name and \
                             this.heuristic.definition.score == that.heuristic.definition.score and \
                             this.heuristic.definition.signature_score_map == \
                             that.heuristic.definition.signature_score_map

        result_heuristic_equality = heuristic_equality and \
                                    this.heuristic.attack_ids == that.heuristic.attack_ids and \
                                    this.heuristic.frequency == that.heuristic.frequency and \
                                    this.heuristic.heur_id == that.heuristic.heur_id and \
                                    this.heuristic.score == that.heuristic.score and \
                                    this.heuristic.score_map == that.heuristic.score_map and \
                                    this.heuristic.signatures == that.heuristic.signatures

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = result_heuristic_equality and \
                               this.body == that.body and \
                               this.body_format == that.body_format and \
                               this.classification == that.classification and \
                               this.depth == that.depth and \
                               len(this.subsections) == len(that.subsections) and \
                               this.title_text == that.title_text and \
                               this.tags == that.tags

    if not current_section_equality:
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(subsection, that.subsections[index])
        if not subsection_equality:
            return False

    return True


def create_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if not os.path.exists(temp_service_config_path):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)


def remove_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if os.path.exists(temp_service_config_path):
        os.remove(temp_service_config_path)


@pytest.fixture
def kaspersky_icap_client_class():
    create_tmp_manifest()
    try:
        from kaspersky import KasperskyIcapClient
        yield KasperskyIcapClient
    finally:
        remove_tmp_manifest()


@pytest.fixture
def kaspersky_class_instance():
    create_tmp_manifest()
    try:
        from kaspersky import Kaspersky
        yield Kaspersky()
    finally:
        remove_tmp_manifest()


@pytest.fixture
def dummy_result_class_instance():
    class DummyResult(object):
        from assemblyline_v4_service.common.result import ResultSection

        def __init__(self):
            self.sections = []

        def add_section(self, res_sec: ResultSection):
            self.sections.append(res_sec)
    return DummyResult()


class TestKasperskyIcapClient:
    @staticmethod
    def test_init(kaspersky_icap_client_class):
        kaspersky_icap_client_class("localhost", 1344, "resp")
        assert True

    @staticmethod
    def test_get_kaspersky_version(kaspersky_icap_client_class, mocker):
        from assemblyline_v4_service.common.icap import IcapClient
        kasp_instance = kaspersky_icap_client_class("blah", 1234, "blah")
        mocker.patch.object(IcapClient, "options_respmod", return_value="blah")
        assert kasp_instance.get_kaspersky_version() == "unknown"
        mocker.patch.object(IcapClient, "options_respmod", return_value="blah\r\nblah\r\nServer: blahblah\r\n")
        assert kasp_instance.get_kaspersky_version() == "blahblah"


class TestKaspersky:
    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            os.remove(temp_sample_path)

    @staticmethod
    def test_init(kaspersky_class_instance):
        assert kaspersky_class_instance.icap_host == ""
        assert kaspersky_class_instance.icap_port == 0
        assert kaspersky_class_instance.respmod_endpoint == ""
        assert kaspersky_class_instance.icap is None

    @staticmethod
    def test_start(kaspersky_class_instance):
        from kaspersky import KasperskyIcapClient
        kaspersky_class_instance.start()
        assert kaspersky_class_instance.icap_host == kaspersky_class_instance.config["icap_host"]
        assert kaspersky_class_instance.icap_port == kaspersky_class_instance.config["icap_port"]
        assert kaspersky_class_instance.respmod_endpoint == kaspersky_class_instance.config["respmod_endpoint"]
        assert isinstance(kaspersky_class_instance.icap, KasperskyIcapClient)

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, kaspersky_class_instance, mocker):
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from kaspersky import Kaspersky

        kaspersky_class_instance.start()

        service_task = ServiceTask(sample)
        task = Task(service_task)
        kaspersky_class_instance._task = task
        service_request = ServiceRequest(task)

        # For coverage
        service_request.task.deep_scan = True
        mocker.patch.object(Kaspersky, "_add_debug_information")

        # Actually executing the sample
        kaspersky_class_instance.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = json.loads(f.read())
        f.close()

        # Assert that the appropriate sections of the dict are equal

        # Avoiding unique items in the response
        test_result_response = test_result.pop("response")
        correct_result_response = correct_result.pop("response")
        assert test_result == correct_result

        # Comparing everything in the response except for the service_completed and the output.json supplementary
        test_result_response["milestones"].pop("service_completed")
        correct_result_response["milestones"].pop("service_completed")
        correct_result_response.pop("supplementary")
        test_result_response.pop("supplementary")
        assert test_result_response == correct_result_response

    @staticmethod
    @pytest.mark.parametrize(
        "icap_result, expected_section_title, expected_tags, expected_heuristic",
        [
            ("", "", {}, 0),
            ("blah\nblah\nblah\nblah", "", {}, 0),
            ("blah\nX-Virus-ID: virus_name\nblah\nblah", "virus_name", {"av.virus_name": ["virus_name"]}, 1),
        ]
    )
    def test_icap_to_alresult(icap_result, expected_section_title, expected_tags, expected_heuristic, kaspersky_class_instance, dummy_result_class_instance):
        from assemblyline_v4_service.common.result import ResultSection, Heuristic

        if not icap_result:
            with pytest.raises(Exception):
                kaspersky_class_instance._icap_to_alresult(dummy_result_class_instance, icap_result)
            return

        kaspersky_class_instance._icap_to_alresult(dummy_result_class_instance, icap_result)
        if not expected_section_title:
            assert dummy_result_class_instance.sections == []
        else:
            correct_result_section = ResultSection(expected_section_title)
            correct_result_section.heuristic = Heuristic(expected_heuristic) if expected_heuristic else None
            correct_result_section.tags = expected_tags
            assert check_section_equality(dummy_result_class_instance.sections[0], correct_result_section)

    @staticmethod
    def test_add_debug_information(kaspersky_class_instance, dummy_result_class_instance, mocker):
        from kaspersky import KasperskyIcapClient
        from assemblyline_v4_service.common.result import ResultSection
        scan_engine_version = "blah"
        mocker.patch.object(KasperskyIcapClient, "get_kaspersky_version", return_value=scan_engine_version)
        kaspersky_class_instance.icap = KasperskyIcapClient("blah", 1, "blah")
        icap_result = "blahblahblah"
        correct_service_version_result_section = ResultSection("Kaspersky Scan Engine Version", body=scan_engine_version)
        correct_debug_info_result_section = ResultSection("ICAP HTTP Response", body=icap_result)
        kaspersky_class_instance._add_debug_information(dummy_result_class_instance, icap_result)
        assert check_section_equality(dummy_result_class_instance.sections[0], correct_service_version_result_section)
        assert check_section_equality(dummy_result_class_instance.sections[1], correct_debug_info_result_section)
