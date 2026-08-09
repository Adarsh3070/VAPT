"""
report.py
Renders scan + vulnerability findings into a self-contained HTML report.
"""

import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

from . import __version__

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def generate_report(target: str, hosts: list, findings: list,
                     out_path: str = "vapt_report.html") -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report.html.j2")

    html = template.render(
        target=target,
        hosts=hosts,
        findings=findings,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        version=__version__,
    )

    with open(out_path, "w") as f:
        f.write(html)

    print(f"[+] Report written to {out_path}")
    return out_path
