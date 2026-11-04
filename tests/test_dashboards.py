# SPDX-License-Identifier: Apache-2.0
"""Keep dashboard queries compatible with the actual exporter, including optional platform readings."""
import json
from pathlib import Path
import re

from mmtest import TempData, base_settings
from test_metrics import machine, resource, document, NOW, MID
import mmprometheus
import storage_fixtures

CODE = Path(__file__).resolve().parent.parent


class Dashboards(TempData):
    def test_zero_storage_fixture_uses_the_shipped_dashboard_query(self):
        dashboard = json.loads((CODE / "monitoring/grafana/dashboards/fleet.json").read_text())
        expression = next(p for p in dashboard["panels"] if p["id"] == 8)["targets"][0]["expr"]
        expression = expression.replace("$job", "machine-manager")
        for variable in ("instance", "machine"):
            expression = expression.replace("${%s}" % variable, ".*")
        fixtures = json.loads((CODE / "monitoring/tests/alerts.test.yml").read_text())
        case = next(t for t in fixtures["tests"] if t["name"] == "zero storage size remains unknown")
        self.assertIn({"expr": expression, "eval_time": "20m", "exp_samples": []}, case["promql_expr_test"])

    def test_zero_filesystem_fixture_uses_the_shipped_storage_query(self):
        dashboard = json.loads((CODE / "monitoring/grafana/dashboards/storage.json").read_text())
        expression = next(p for p in dashboard["panels"] if p["id"] == 6)["targets"][0]["expr"]
        expression = expression.replace("$job", "machine-manager")
        for variable in ("instance", "machine"):
            expression = expression.replace("${%s}" % variable, ".*")
        fixtures = json.loads((CODE / "monitoring/tests/alerts.test.yml").read_text())
        case = next(t for t in fixtures["tests"] if t["name"] == "zero filesystem size remains unknown")
        self.assertIn({"expr": expression, "eval_time": "30m", "exp_samples": []}, case["promql_expr_test"])

    def test_dashboard_metric_families_are_exported(self):
        source = machine(readings={"free_pct": 50, "cpu_pct": 30, "sys_pct": 5, "comp_mb": 10,
                                   "swap_used_mb": 2, "psi_some_pct": 1, "psi_full_pct": 0})
        text, _ = mmprometheus.render(MID, source, document(resource()), (), NOW, base_settings(),
                                      storage=[(MID, storage_fixtures.snapshot(), True)])
        exported = set(re.findall(r"^# TYPE (machine_manager_\w+)", text, re.M))
        for path in sorted((CODE / "monitoring/grafana/dashboards").glob("*.json")):
            dashboard = json.loads(path.read_text())
            for panel in dashboard["panels"]:
                for target in panel["targets"]:
                    names = set(re.findall(r"\bmachine_manager_\w+", target["expr"]))
                    with self.subTest(dashboard=path.name, panel=panel["title"]):
                        self.assertFalse(names - exported, "dashboard uses a metric the exporter did not emit")

    def test_dashboard_queries_keep_producer_and_machine_filters(self):
        for path in sorted((CODE / "monitoring/grafana/dashboards").glob("*.json")):
            self.assertNotIn(":regex", path.read_text(), "Prometheus must escape selected label values")
            for panel in json.loads(path.read_text())["panels"]:
                for target in panel["targets"]:
                    expr = target["expr"]
                    with self.subTest(dashboard=path.name, panel=panel["title"]):
                        self.assertIn('job="$job"', expr)
                        self.assertIn('instance=~"${instance}"', expr)
                        if "machine_manager_" in expr and "snapshot_valid" not in expr:
                            self.assertIn('machine_id=~"${machine}"', expr)
                        self.assertNotRegex(expr, r"\b(rate|increase|sum)\s*\(")
                        self.assertNotRegex(expr, r"\bor\s+(vector\s*\(\s*0|0\b)")
                if panel["type"] == "timeseries":
                    self.assertFalse(panel["fieldConfig"]["defaults"]["custom"]["spanNulls"])

    def test_storage_dashboard_is_linked_and_shows_each_storage_family_without_totals(self):
        boards = {path.name: json.loads(path.read_text())
                  for path in (CODE / "monitoring/grafana/dashboards").glob("*.json")}
        storage = boards.pop("storage.json")
        self.assertEqual(storage["uid"], "mm-storage")
        fleet = boards["fleet.json"]
        self.assertIn("/d/mm-storage", [link["url"] for link in fleet["links"]])
        self.assertEqual([v["name"] for v in storage["templating"]["list"]],
                         [v["name"] for v in fleet["templating"]["list"]])
        self.assertEqual(len({p["id"] for p in storage["panels"]}), len(storage["panels"]))
        exprs = " ".join(t["expr"] for p in storage["panels"] for t in p["targets"])
        for name in ("snapshot_fresh", "snapshot_timestamp_seconds", "inventory_state", "filesystem_size_bytes",
                     "filesystem_available_bytes", "filesystem_used_bytes", "device_read_bytes_per_second",
                     "device_write_bytes_per_second", "device_read_ops_per_second", "device_write_ops_per_second"):
            self.assertIn("machine_manager_storage_" + name + "{", exprs)
        self.assertNotRegex(exprs, r"\b(by|without)\s*\(|\b(avg|min|max|count|topk|bottomk|group)\s*\(")
