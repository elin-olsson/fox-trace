import json
import os
import webbrowser


class FoxVisualizer:
    def __init__(self, data_path="data/findings.json", output_path="data/shadow_map.html"):
        self.data_path = data_path
        self.output_path = output_path

    def _prepare_graph_data(self, data):
        blast_data = data.get("blast_radius", {})
        alerts_by_key = {}
        system_alerts = []
        for alert in data.get("risk_alerts", []):
            key = alert.get("key")
            if key:
                alerts_by_key.setdefault(key, []).append(alert)
            else:
                system_alerts.append(alert)

        nodes = [{
            "id": "localhost",
            "label": "Local Machine",
            "type": "origin",
            "radius": 15,
            "alerts": system_alerts
        }]
        links = []

        for key in data.get("public_keys", []):
            key_name = key["name"].replace(".pub", "")
            key_id = f"key_{key['fingerprint'] or key['name']}"
            radius_info = blast_data.get(key_name, {"percentage": 0, "count": 0})
            nodes.append({
                "id": key_id,
                "label": f"Key: {key['name']}",
                "type": "key",
                "comment": key.get("comment", ""),
                "blast_radius": radius_info["percentage"],
                "blast_count": radius_info["count"],
                "radius": 10 + (radius_info["percentage"] / 10),
                "alerts": alerts_by_key.get(key_name, [])
            })
            links.append({"source": "localhost", "target": key_id})

        seen_hosts = set()
        for host in data.get("known_hosts", []):
            host_id = f"host_{host['host']}"
            if host_id not in seen_hosts:
                seen_hosts.add(host_id)
                nodes.append({
                    "id": host_id,
                    "label": host["host"],
                    "type": "host",
                    "is_hashed": host.get("is_hashed", False),
                    "radius": 8,
                    "alerts": []
                })
            links.append({"source": "localhost", "target": host_id})

        return {"nodes": nodes, "links": links}

    def generate(self):
        if not os.path.exists(self.data_path):
            print(f"Error: {self.data_path} not found. Run harvester first.")
            return False

        with open(self.data_path) as f:
            raw_data = json.load(f)

        graph_data = self._prepare_graph_data(raw_data)
        if len(graph_data["nodes"]) <= 1:
            print("[!] No data to visualize. Run the harvester first.")
            return False

        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Fox-trace | Shadow Map</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{ background-color: #050a0f; color: #00d4ff; font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; overflow: hidden; }}
        .node circle {{ stroke: #1a2a3a; stroke-width: 2px; }}
        .node text {{ fill: #e0e0e0; font-size: 11px; pointer-events: none; text-shadow: 1px 1px 2px #000; }}
        .link {{ stroke: #1a2a3a; stroke-opacity: 0.4; stroke-width: 1.2px; }}
        #header {{ position: absolute; top: 20px; left: 20px; z-index: 10; }}
        #header h1 {{ font-family: 'Courier New', monospace; letter-spacing: 2px; margin: 0; text-shadow: 0 0 10px #00d4ff44; }}
        #header p {{ font-size: 0.8em; color: #5a6b7a; margin: 5px 0 0 0; }}
        #details {{
            position: absolute; bottom: 20px; right: 20px;
            background: rgba(13, 20, 27, 0.95); padding: 20px;
            border: 1px solid #1a2a3a; border-radius: 8px;
            width: 320px; display: none; z-index: 10;
            box-shadow: 0 4px 20px rgba(0,0,0,0.6);
            backdrop-filter: blur(5px);
        }}
        .legend {{ position: absolute; top: 20px; right: 20px; font-size: 12px; z-index: 10; }}
        .legend-item {{ display: flex; align-items: center; margin-bottom: 6px; color: #8a9baa; }}
        .dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 12px; flex-shrink: 0; }}
        .blast-badge {{ background: #ff4d4d22; color: #ff4d4d; border: 1px solid #ff4d4d44; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        .alert-HIGH {{ color: #ff4d4d; }}
        .alert-MEDIUM {{ color: #ffaa4d; }}
        .alert-LOW {{ color: #ffdd4d; }}
    </style>
</head>
<body>
    <div id="header">
        <h1>FOX-TRACE // SHADOW MAP</h1>
        <p>SSH Trust &amp; Blast Radius Analysis</p>
    </div>
    <div class="legend">
        <div class="legend-item"><div class="dot" style="background:#00d4ff"></div>Local Machine</div>
        <div class="legend-item"><div class="dot" style="background:#40ffaa"></div>SSH Keys (size = Blast Radius)</div>
        <div class="legend-item"><div class="dot" style="background:#ff944d"></div>Known Hosts</div>
    </div>
    <div id="details"></div>
    <script>
        const data = {json.dumps(graph_data)};
        const width = window.innerWidth, height = window.innerHeight;

        function esc(s) {{
            return String(s)
                .replace(/&/g, "&amp;").replace(/</g, "&lt;")
                .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        }}

        const svg = d3.select("body").append("svg").attr("width", width).attr("height", height);
        svg.call(d3.zoom().on("zoom", e => g.attr("transform", e.transform)));
        const g = svg.append("g");

        const simulation = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.links).id(d => d.id).distance(200))
            .force("charge", d3.forceManyBody().strength(-500))
            .force("center", d3.forceCenter(width / 2, height / 2));

        const link = g.append("g").selectAll("line")
            .data(data.links).enter().append("line").attr("class", "link");

        const node = g.append("g").selectAll("g")
            .data(data.nodes).enter().append("g").attr("class", "node")
            .call(d3.drag()
                .on("start", (e, d) => {{ if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
                .on("drag",  (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
                .on("end",   (e, d) => {{ if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }}))
            .on("click", (event, d) => {{
                const panel = d3.select("#details");
                let html = "<h3 style='margin:0 0 10px 0;color:#00d4ff'>" + esc(d.type.toUpperCase()) + "</h3>";
                html += "<strong>Label:</strong> " + esc(d.label) + "<br>";
                if (d.type === "key") {{
                    html += "<strong>Blast Radius:</strong> " + esc(d.blast_radius) + "% (" + esc(d.blast_count) + " hosts)<br>";
                    if (d.blast_radius > 50) html += "<span class='blast-badge'>HIGH EXPOSURE</span><br>";
                    if (d.comment) html += "<strong>Comment:</strong> " + esc(d.comment) + "<br>";
                }}
                if (d.alerts && d.alerts.length > 0) {{
                    html += "<br><strong>Alerts:</strong><br>";
                    d.alerts.forEach(a => {{
                        html += "<span class='alert-" + esc(a.level) + "'>[" + esc(a.level) + "] " + esc(a.message) + "</span><br>";
                    }});
                }}
                panel.style("display", "block").html(html);
            }});

        node.append("circle")
            .attr("r", d => d.radius)
            .attr("fill", d => ({{origin:"#00d4ff", key:"#40ffaa", host:"#ff944d"}})[d.type] || "#999")
            .style("filter", d =>
                (d.alerts && d.alerts.some(a => a.level === "HIGH")) ||
                (d.type === "key" && d.blast_radius > 50)
                    ? "drop-shadow(0 0 8px rgba(255,77,77,0.6))" : "none");

        node.append("text").attr("dx", d => d.radius + 5).attr("dy", ".35em").text(d => d.label);

        simulation.on("tick", () => {{
            link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
            node.attr("transform", d => `translate(${{d.x}},${{d.y}})`);
        }});
    </script>
</body>
</html>"""

        with open(self.output_path, "w") as f:
            f.write(html)

        print(f"[SUCCESS] Shadow Map generated: {self.output_path}")
        try:
            webbrowser.open("file://" + os.path.abspath(self.output_path))
        except Exception:
            pass
        return True


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Fox-trace visualizer")
    parser.add_argument("--data", default="data/findings.json", help="Input JSON")
    parser.add_argument("--out", default="data/shadow_map.html", help="Output HTML")
    args = parser.parse_args()
    FoxVisualizer(data_path=args.data, output_path=args.out).generate()
