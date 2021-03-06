import unittest
import copy
import json
from . import ValidatorTest
from .. import validate_string

VALID_INDICATOR = """
{
    "type": "indicator",
    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "source--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48Z",
    "modified": "2016-04-06T20:03:48Z",
    "version": 1,
    "labels": ["malicious-activity"],
    "name": "Poison Ivy Malware",
    "description": "This file is part of Poison Ivy",
    "pattern": "file-object.hashes.md5 = '3773a88f65a5e780c8dff9cdc3a056f3'",
    "pattern_lang": "cybox",
    "pattern_lang_version": "1.0",
    "valid_from": "2016-04-06T20:03:48Z",
    "valid_from_precision": "full"
}
"""


class IndicatorTestCases(ValidatorTest):
    valid_indicator = json.loads(VALID_INDICATOR)

    def test_wellformed_indicator(self):
        results = validate_string(VALID_INDICATOR, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_modified_before_created(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['modified'] = "2001-04-06T20:03:48Z"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_version_equal_created_and_modified(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['version'] = 2
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_version_unequal_created_and_modified(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['created'] = "2001-04-06T20:03:48Z"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_cybox_version(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern_lang_version'] = "2.0"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_custom_property_name_invalid_character(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['my_new_property!'] = "abc123"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_custom_property_name_short(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['mp'] = "abc123"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_custom_property_name_long(self):
        indicator = copy.deepcopy(self.valid_indicator)
        long_property_name = 'my_new_property_' * 16
        indicator[long_property_name] = "abc123"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_empty_list(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['my_new_property'] = []
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_id_type(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['id'] = "something--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_timestamp_precision_name(self):
        indicator = copy.deepcopy(self.valid_indicator)
        del indicator['valid_from_precision']
        indicator['something_precision'] = "full"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_timestamp_precision_year(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['valid_from_precision'] = "year"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_timestamp_precision_month(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['valid_from_precision'] = "month"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_timestamp_precision_day(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['valid_from_precision'] = "day"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_timestamp_precision_hour(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['valid_from_precision'] = "hour"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_timestamp_precision_minute(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['valid_from_precision'] = "minute"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_timestamp_precision_minute_valid(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['valid_from_precision'] = "minute"
        indicator['valid_from'] = "2016-04-06T20:03:00Z"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_timestamp_precision_hour_valid(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['valid_from_precision'] = "hour"
        indicator['valid_from'] = "2016-04-06T20:00:00Z"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_timestamp_precision_day_valid(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['valid_from_precision'] = "day"
        indicator['valid_from'] = "2016-04-06T00:00:00Z"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_timestamp_precision_month_valid(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['valid_from_precision'] = "month"
        indicator['valid_from'] = "2016-04-01T00:00:00Z"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_timestamp_precision_year_valid(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['valid_from_precision'] = "year"
        indicator['valid_from'] = "2016-01-01T00:00:00Z"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertTrue(results.is_valid)

    def test_reserved_property_confidence(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['confidence'] = "Something"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_severity(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['severity'] = "Something"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_action(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['action'] = "Something"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_usernames(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['usernames'] = "Something"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_phone_numbers(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['phone_numbers'] = "Something"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_reserved_property_addresses(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['addresses'] = "Something"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_reserved_object_type_incident(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['type'] = "incident"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_reserved_object_type_infrastructure(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['type'] = "infrastructure"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

    def test_vocab_indicator_label(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['labels'] = ["suspicious"]
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

        self.check_ignore(indicator, 'indicator-label')

    def test_vocab_pattern_lang(self):
        indicator = copy.deepcopy(self.valid_indicator)
        indicator['pattern_lang'] = "something"
        indicator = json.dumps(indicator)
        results = validate_string(indicator, self.options).schema_results
        self.assertEqual(results.is_valid, False)

        self.check_ignore(indicator, 'pattern-lang')


if __name__ == "__main__":
    unittest.main()
