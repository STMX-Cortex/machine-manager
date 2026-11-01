# SPDX-License-Identifier: Apache-2.0
"""Keep dashboard queries compatible with the actual exporter, including optional platform readings."""
import json
from pathlib import Path
import re

from mmtest import TempData, base_settings
from test_metrics import machine, resource, document, NOW, MID
import mmprometheus

CODE = Path(__file__).resolve().parent.parent


class Dashboards(TempData):
    def test_dashboard_metric_families_are_exported(self):
        source = machine(readings={"free_pct": 50, "cpu_pct": 30, "sys_pct": 5, "comp_mb": 10,
                                   "swap_used_mb": 2, "psi_some_pct": 1, "psi_full_pct": 0})
        text, _ = mmprometheus.render(MID, source, document(resource()), (), NOW, base_settings())
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
            for panel in json.loads(path.read_text())["panels"]:
                for target in panel["targets"]:
                    expr = target["expr"]
                    with self.subTest(dashboard=path.name, panel=panel["title"]):
                        self.assertIn('job="$job"', expr)
                        self.assertIn('instance=~"${instance:regex}"', expr)
                        if "machine_manager_" in expr and "snapshot_valid" not in expr:
                            self.assertIn('machine_id=~"${machine:regex}"', expr)
                        self.assertNotRegex(expr, r"\b(rate|increase|sum)\s*\(")
                        self.assertNotRegex(expr, r"\bor\s+(vector\s*\(\s*0|0\b)")
                if panel["type"] == "timeseries":
                    self.assertFalse(panel["fieldConfig"]["defaults"]["custom"]["spanNulls"])
