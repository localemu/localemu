from localemu.services.logs.provider import get_pattern_matcher


class TestCloudWatchLogs:
    def test_get_pattern_matcher(self):
        def assert_match(filter_pattern, log_event, expected):
            matches = get_pattern_matcher(filter_pattern)
            assert matches(filter_pattern, log_event) == expected

        # JSON selector pattern: $.message = "Failed" matches the parsed JSON message
        assert_match('{$.message = "Failed"}', {"message": '{"message":"Failed"}'}, True)
        # Term-based pattern: "ERROR" must appear in the message text
        assert_match("ERROR", {"message": "Failed"}, False)
        assert_match("ERROR", {"message": "ERROR occurred"}, True)
        # Empty pattern matches everything
        assert_match("", {"message": "FooBar"}, True)
        # Column/bracket pattern not natively supported — falls through to substring match
        assert_match("[w1=Failed]", {"message": "Failed"}, False)
        assert_match("[w1=Failed]", {"message": "[w1=Failed]"}, True)
