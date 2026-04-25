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
            "risk_score": data.get("risk_score", 0),
            "alerts": system_alerts,
        }]
        links = []

        for key in data.get("public_keys", []):
            key_name = key["name"].replace(".pub", "")
            key_id = f"key_{key.get('fingerprint') or key['name']}"
            r = blast_data.get(key_name, {"percentage": 0, "count": 0, "confidence": "potential"})
            encrypted = True  # public key — no passphrase concept, assume safe

            # Find matching private key for passphrase info
            for priv in data.get("private_keys", []):
                if priv["name"].replace(".pub", "") == key_name or priv["name"] == key_name:
                    encrypted = priv.get("encrypted", False)
                    break

            nodes.append({
                "id": key_id,
                "label": f"Key: {key['name']}",
                "type": "key",
                "key_type": key.get("key_type", "Unknown"),
                "comment": key.get("comment", ""),
                "blast_radius": r["percentage"],
                "blast_count": r["count"],
                "blast_confidence": r.get("confidence", "potential"),
                "encrypted": encrypted,
                "radius": 10 + (r["percentage"] / 10),
                "alerts": alerts_by_key.get(key_name, []),
            })
            links.append({"source": "localhost", "target": key_id})

        seen = set()
        for host in data.get("known_hosts", []):
            host_id = f"host_{host['host']}"
            if host_id not in seen:
                seen.add(host_id)
                nodes.append({
                    "id": host_id,
                    "label": host["host"],
                    "type": "host",
                    "is_hashed": host.get("is_hashed", False),
                    "radius": 8,
                    "alerts": [],
                })
            links.append({"source": "localhost", "target": host_id})

        return {"nodes": nodes, "links": links}

    def generate(self):
        if not os.path.exists(self.data_path):
            print(f"Error: {self.data_path} not found. Run harvester first.")
            return False

        with open(self.data_path) as f:
            raw = json.load(f)

        graph = self._prepare_graph_data(raw)
        if len(graph["nodes"]) <= 1:
            print("[!] No data to visualize. Run the harvester first.")
            return False

        risk_score = raw.get("risk_score", 0)
        risk_label = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 60 else "HIGH"
        risk_color = "#40ffaa" if risk_score < 30 else "#ffaa4d" if risk_score < 60 else "#ff4d4d"

        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Fox-trace | Shadow Map</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ background: #050a0f; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; overflow: hidden; }}
        .node circle {{ stroke: #1a2a3a; stroke-width: 2px; }}
        .node text {{ fill: #e0e0e0; font-size: 11px; pointer-events: none; text-shadow: 1px 1px 2px #000; }}
        .link {{ stroke: #1a2a3a; stroke-opacity: 0.4; stroke-width: 1.2px; }}
        #header {{ position: absolute; top: 20px; left: 20px; z-index: 10; }}
        #header h1 {{ font-family: 'Courier New', monospace; letter-spacing: 2px; margin: 0; color: #00d4ff; text-shadow: 0 0 10px #00d4ff44; }}
        #header p {{ font-size: 0.8em; color: #5a6b7a; margin: 4px 0 0 0; }}
        #risk-badge {{
            display: inline-block; margin-top: 8px;
            background: {risk_color}22; color: {risk_color};
            border: 1px solid {risk_color}66; border-radius: 4px;
            font-family: 'Courier New', monospace; font-size: 0.75em;
            padding: 3px 10px; letter-spacing: 1px;
        }}
        #details {{
            position: absolute; bottom: 20px; right: 20px;
            background: rgba(13,20,27,0.96); padding: 20px;
            border: 1px solid #1a2a3a; border-radius: 8px;
            width: 330px; display: none; z-index: 10;
            box-shadow: 0 4px 20px rgba(0,0,0,0.6);
        }}
        #details h3 {{ margin: 0 0 10px 0; color: #00d4ff; font-size: 0.85em; letter-spacing: 1px; }}
        #details .row {{ display: flex; justify-content: space-between; font-size: 0.8em; margin-bottom: 4px; color: #8a9baa; }}
        #details .row span:last-child {{ color: #e0e0e0; }}
        #details .alert-HIGH   {{ color: #ff4d4d; font-size: 0.78em; margin-top: 4px; }}
        #details .alert-MEDIUM {{ color: #ffaa4d; font-size: 0.78em; margin-top: 4px; }}
        #details .alert-LOW    {{ color: #ffdd4d; font-size: 0.78em; margin-top: 4px; }}
        .legend {{ position: absolute; top: 20px; right: 20px; font-size: 12px; z-index: 10; }}
        .legend-item {{ display: flex; align-items: center; margin-bottom: 6px; color: #8a9baa; }}
        .dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 12px; flex-shrink: 0; }}
        .close-btn {{ float: right; cursor: pointer; color: #5a6b7a; font-size: 0.8em; }}
        .close-btn:hover {{ color: #00d4ff; }}
    </style>
</head>
<body>
    <div id="header">
        <h1>FOX-TRACE // SHADOW MAP</h1>
        <p>SSH Trust &amp; Lateral Movement Analysis</p>
        <div id="risk-badge">RISK SCORE: {risk_score}/100 — {risk_label}</div>
    </div>
    <div class="legend">
        <div class="legend-item"><div class="dot" style="background:#00d4ff"></div>Local Machine</div>
        <div class="legend-item"><div class="dot" style="background:#40ffaa"></div>Key — encrypted</div>
        <div class="legend-item"><div class="dot" style="background:#ff4d4d"></div>Key — no passphrase</div>
        <div class="legend-item"><div class="dot" style="background:#ff944d"></div>Known Host</div>
    </div>
    <div id="details"></div>
    <script>
        const data = {json.dumps(graph)};
        const W = window.innerWidth, H = window.innerHeight;

        function esc(s) {{
            return String(s ?? "")
                .replace(/&/g,"&amp;").replace(/</g,"&lt;")
                .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
        }}

        const svg = d3.select("body").append("svg").attr("width", W).attr("height", H);
        svg.call(d3.zoom().on("zoom", e => g.attr("transform", e.transform)));
        const g = svg.append("g");

        const sim = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.links).id(d => d.id).distance(200))
            .force("charge", d3.forceManyBody().strength(-500))
            .force("center", d3.forceCenter(W / 2, H / 2));

        const link = g.append("g").selectAll("line")
            .data(data.links).enter().append("line").attr("class","link");

        const node = g.append("g").selectAll("g")
            .data(data.nodes).enter().append("g").attr("class","node")
            .call(d3.drag()
                .on("start", (e,d) => {{ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
                .on("drag",  (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
                .on("end",   (e,d) => {{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}))
            .on("click", (event,d) => {{
                const panel = d3.select("#details");
                let h = "<span class='close-btn' onclick=\"document.getElementById('details').style.display='none'\">✕ close</span>";
                h += "<h3>" + esc(d.type.toUpperCase()) + "</h3>";
                h += "<div class='row'><span>Label</span><span>" + esc(d.label) + "</span></div>";

                if (d.type === "key") {{
                    h += "<div class='row'><span>Type</span><span>" + esc(d.key_type) + "</span></div>";
                    h += "<div class='row'><span>Passphrase</span><span>" + (d.encrypted ? "✓ encrypted" : "✗ none") + "</span></div>";
                    h += "<div class='row'><span>Blast Radius</span><span>" + esc(d.blast_radius) + "% (" + esc(d.blast_count) + " hosts)</span></div>";
                    h += "<div class='row'><span>Confidence</span><span>" + esc(d.blast_confidence) + "</span></div>";
                    if (d.comment && d.comment !== "None") {{
                        h += "<div class='row'><span>Comment</span><span>" + esc(d.comment) + "</span></div>";
                    }}
                }}
                if (d.type === "origin" && d.risk_score !== undefined) {{
                    h += "<div class='row'><span>Risk Score</span><span>" + esc(d.risk_score) + "/100</span></div>";
                }}
                if (d.alerts && d.alerts.length > 0) {{
                    h += "<br>";
                    d.alerts.forEach(a => {{
                        h += "<div class='alert-" + esc(a.level) + "'>[" + esc(a.level) + "] " + esc(a.message) + "</div>";
                    }});
                }}
                panel.style("display","block").html(h);
            }});

        node.append("circle")
            .attr("r", d => d.radius)
            .attr("fill", d => {{
                if (d.type === "origin") return "#00d4ff";
                if (d.type === "host")   return "#ff944d";
                if (d.type === "key")    return d.encrypted ? "#40ffaa" : "#ff4d4d";
                return "#999";
            }})
            .style("filter", d => {{
                const hasHighAlert = d.alerts && d.alerts.some(a => a.level === "HIGH");
                if (hasHighAlert || (d.type === "key" && !d.encrypted))
                    return "drop-shadow(0 0 8px rgba(255,77,77,0.7))";
                if (d.type === "key" && d.blast_radius > 50)
                    return "drop-shadow(0 0 6px rgba(255,170,77,0.5))";
                return "none";
            }});

        node.append("text")
            .attr("dx", d => d.radius + 5)
            .attr("dy", ".35em")
            .text(d => d.label);

        sim.on("tick", () => {{
            link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
                .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
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
    parser.add_argument("--data", default="data/findings.json")
    parser.add_argument("--out", default="data/shadow_map.html")
    args = parser.parse_args()
    FoxVisualizer(data_path=args.data, output_path=args.out).generate()
