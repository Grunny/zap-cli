"""
Tests for the ZAP CLI helpers.

.. moduleauthor:: Daniel Grunwell (grunny)
"""

import unittest

from ddt import ddt, data, unpack

from zapcli import helpers


@ddt
class ZAPCliHelperTestCase(unittest.TestCase):
    """Test ZAP CLI Helper methods."""

    @data(
        (
            [
                {'id': 1, 'value': 'one'},
                {'id': 5, 'value': 'five'},
                {'id': 10, 'value': 'ten'}
            ],
            [1],
            [{'id': 1, 'value': 'one'}]
        ),
        (
            [
                {'id': 1, 'value': 'one'},
                {'id': 5, 'value': 'five'},
                {'id': 10, 'value': 'ten'}
            ],
            [1, 10],
            [
                {'id': 1, 'value': 'one'},
                {'id': 10, 'value': 'ten'}
            ]
        ),
        (
            [
                {'id': 1, 'value': 'one'},
                {'id': 5, 'value': 'five'},
                {'id': 10, 'value': 'ten'}
            ],
            [4],
            []
        ),
        (
            [
                {'id': 1, 'value': 'one'},
                {'id': 5, 'value': 'five'},
                {'id': 10, 'value': 'ten'}
            ],
            [],
            [
                {'id': 1, 'value': 'one'},
                {'id': 5, 'value': 'five'},
                {'id': 10, 'value': 'ten'}
            ]
        ),
        (
            [],
            [],
            []
        )
    )
    @unpack
    def test_filter_by_ids(self, original_list, ids_to_filter, expected_result):
        """Test the function for filtering a list of dicts by IDs."""
        result = helpers.filter_by_ids(original_list, ids_to_filter)

        self.assertEqual(result, expected_result)


if __name__ == '__main__':
    unittest.main()
