from localemu.services.cloudtrail import recording_hook as rh


def test_each_measured_service_uses_its_own_delay():
    for service, delay in rh._EVB_FORWARDING_DELAY_BY_SERVICE.items():
        assert rh._forwarding_delay(service) == delay


def test_service_name_is_case_insensitive():
    assert rh._forwarding_delay("IAM") == rh._EVB_FORWARDING_DELAY_BY_SERVICE["iam"]


def test_unknown_or_missing_service_uses_the_default():
    assert rh._forwarding_delay("somenewservice") == rh._EVB_FORWARDING_DELAY_SECONDS
    assert rh._forwarding_delay("") == rh._EVB_FORWARDING_DELAY_SECONDS
    assert rh._forwarding_delay(None) == rh._EVB_FORWARDING_DELAY_SECONDS


def test_iam_is_delivered_before_sqs():
    assert rh._forwarding_delay("iam") < rh._forwarding_delay("sqs")
