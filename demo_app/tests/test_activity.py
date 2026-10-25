"""Pure telemetry tests; no user keys, model loads or database writes."""
import json
import unittest

from demo_app.activity import BackendActivity


class ActivityTests(unittest.TestCase):
    def test_bounded_read_only_snapshots(self):
        activity = BackendActivity()
        for _ in range(300):
            item = activity.start('admin', 'analysis')
            activity.finish(item, 200, {'sessions': 1})
        first = activity.snapshot()
        self.assertEqual(len(first['events']), 250)
        self.assertEqual(first['active_commands'], 0)
        self.assertEqual(first, activity.snapshot())

    def test_completion_is_idempotent(self):
        activity = BackendActivity()
        item = activity.start('grc', 'review')
        self.assertEqual(activity.snapshot()['active_commands'], 1)
        activity.finish(item, 200, {'demo_records_written': 1})
        first = activity.snapshot()
        activity.finish(item, 500, {})
        self.assertEqual(activity.snapshot(), first)

    def test_only_safe_numeric_response_fields_enter_feed(self):
        activity = BackendActivity()
        item = activity.start('soc', 'review')
        activity.finish(item, 200, {'demo_records_written': 19, 'reason': 'PRIVATE-REASON',
                                    'key': 'PRIVATE-KEY', 'sessions': 'PRIVATE-TEXT'})
        snapshot = activity.snapshot()
        self.assertNotIn('PRIVATE', json.dumps(snapshot))
        self.assertEqual(snapshot['events'][-1]['demo_records_written'], 19)

    def test_returned_events_cannot_change_server_state(self):
        activity = BackendActivity()
        snapshot = activity.snapshot()
        snapshot['events'][0]['message'] = 'tampered'
        self.assertNotEqual(snapshot, activity.snapshot())
