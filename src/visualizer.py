import ipaddress
import json
import os
import re
import webbrowser
from datetime import datetime


class FoxVisualizer:
    def __init__(self, data_path="data/findings.json", output_path="data/shadow_map.html"):
        self.data_path = data_path
        self.output_path = output_path

    @staticmethod
    def _host_category(host):
        h = re.sub(r'^\[(.+)\]:\d+$', r'\1', host)
        if h in ('localhost', '127.0.0.1', '::1'):
            return 'loopback'
        if h in ('github.com', 'gitlab.com', 'bitbucket.org'):
            return 'service'
        try:
            return 'private' if ipaddress.ip_address(h).is_private else 'external'
        except ValueError:
            return 'external'

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
            encrypted = True

            for priv in data.get("private_keys", []):
                if priv["name"].replace(".pub", "") == key_name or priv["name"] == key_name:
                    encrypted = priv.get("encrypted", False)
                    break

            nodes.append({
                "id": key_id,
                "label": f"Key: {key['name'].replace('.pub', '')}",
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
            links.append({"source": "localhost", "target": key_id, "weight": 1})

        # Count how many times each host appears (one entry per key type in known_hosts)
        host_counts: dict = {}
        host_meta: dict = {}
        for host in data.get("known_hosts", []):
            h = host["host"]
            host_counts[h] = host_counts.get(h, 0) + 1
            host_meta[h] = host

        for h, meta in host_meta.items():
            host_id = f"host_{h}"
            cat = self._host_category(h)
            nodes.append({
                "id": host_id,
                "label": h,
                "type": "host",
                "category": cat,
                "is_hashed": meta.get("is_hashed", False),
                "radius": 7,
                "alerts": [],
            })
            links.append({"source": "localhost", "target": host_id,
                          "weight": host_counts[h]})

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

        generated = datetime.now().strftime("%Y-%m-%d %H:%M")
        n_hosts  = sum(1 for n in graph["nodes"] if n["type"] == "host")
        n_keys   = sum(1 for n in graph["nodes"] if n["type"] == "key")
        n_alerts = len(raw.get("risk_alerts", []))
        alert_color = "#ff4d4d" if n_alerts else "#40ffaa"
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Fox-trace | Shadow Map</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            background: #050a0f;
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            overflow: hidden;
        }}
        body::before {{
            content: '';
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px);
            background-size: 48px 48px;
            pointer-events: none;
            z-index: 0;
        }}
        .node circle {{ stroke: #1a2a3a; stroke-width: 1.5px; }}
        .node text {{
            fill: #8a9baa;
            font-size: 10px;
            font-family: 'Courier New', monospace;
            pointer-events: none;
            text-shadow: 0 1px 3px #000;
        }}
        .link {{ stroke: #00d4ff; stroke-opacity: 0.18; stroke-width: 1px; }}
        #header {{ position: absolute; top: 24px; left: 24px; z-index: 10; }}
        #header h1 {{
            font-family: 'Courier New', monospace;
            letter-spacing: 3px;
            font-size: 1.05em;
            margin: 0;
            color: #00d4ff;
            text-shadow: 0 0 20px #00d4ff44;
            text-transform: uppercase;
        }}
        #header p {{
            font-family: 'Courier New', monospace;
            font-size: 0.7em;
            color: #5a6b7a;
            margin: 6px 0 0 0;
            letter-spacing: 1px;
        }}
        #risk-badge {{
            display: inline-block;
            margin-top: 10px;
            background: {risk_color}12;
            color: {risk_color};
            border: 1px solid {risk_color}44;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.7em;
            padding: 4px 12px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }}
        #details {{
            position: absolute;
            bottom: 24px;
            right: 24px;
            background: #0d141b;
            padding: 22px;
            border: 1px solid #1a2a3a;
            border-radius: 8px;
            width: 350px;
            display: none;
            z-index: 10;
            box-shadow: 0 4px 30px rgba(0,0,0,0.8);
            transition: border-color 0.3s ease;
        }}
        #details:hover {{ border-color: #00d4ff22; }}
        #details h3 {{
            margin: 0 0 14px 0;
            color: #00d4ff;
            font-family: 'Courier New', monospace;
            font-size: 0.72em;
            letter-spacing: 2px;
            text-transform: uppercase;
            border-bottom: 1px solid #1a2a3a;
            padding-bottom: 10px;
        }}
        #details .row {{
            display: flex;
            justify-content: space-between;
            font-size: 0.78em;
            margin-bottom: 6px;
            align-items: baseline;
        }}
        #details .row span:first-child {{
            color: #5a6b7a;
            font-family: 'Courier New', monospace;
            font-size: 0.88em;
            letter-spacing: 0.5px;
            flex-shrink: 0;
        }}
        #details .row span:last-child {{ color: #e0e0e0; text-align: right; margin-left: 12px; }}
        .alerts-header {{
            color: #5a6b7a;
            font-family: 'Courier New', monospace;
            font-size: 0.65em;
            letter-spacing: 2px;
            text-transform: uppercase;
            margin: 14px 0 8px 0;
            border-top: 1px solid #1a2a3a;
            padding-top: 12px;
        }}
        .alert-badge {{
            display: inline-block;
            font-family: 'Courier New', monospace;
            font-size: 0.65em;
            border-radius: 3px;
            padding: 2px 7px;
            letter-spacing: 1px;
            margin-bottom: 3px;
        }}
        .badge-HIGH   {{ background: #ff4d4d18; color: #ff4d4d; border: 1px solid #ff4d4d44; }}
        .badge-MEDIUM {{ background: #ffaa4d18; color: #ffaa4d; border: 1px solid #ffaa4d44; }}
        .badge-LOW    {{ background: #ffdd4d18; color: #ffdd4d; border: 1px solid #ffdd4d44; }}
        .alert-msg {{ font-size: 0.77em; color: #c0c8d0; margin: 3px 0 4px 0; line-height: 1.45; }}
        .alert-fix {{
            font-size: 0.72em;
            color: #40ffaa;
            margin: 2px 0 10px 0;
            padding-left: 8px;
            border-left: 2px solid #40ffaa44;
            line-height: 1.4;
        }}
        .close-btn {{
            float: right;
            cursor: pointer;
            color: #5a6b7a;
            font-family: 'Courier New', monospace;
            font-size: 0.68em;
            letter-spacing: 1px;
            padding: 2px 7px;
            border: 1px solid #1a2a3a;
            border-radius: 3px;
            transition: all 0.2s;
        }}
        .close-btn:hover {{ color: #00d4ff; border-color: #00d4ff44; }}
        .legend {{
            position: absolute;
            top: 24px;
            right: 24px;
            z-index: 10;
        }}
        .legend-title {{
            color: #5a6b7a;
            font-family: 'Courier New', monospace;
            font-size: 0.62em;
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        .legend-item {{ margin-bottom: 7px; }}
        .legend-tag {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.68em;
            background: #0d141b;
            border: 1px solid #1a2a3a;
            border-radius: 4px;
            padding: 4px 10px;
            color: #8a9baa;
            letter-spacing: 0.5px;
        }}
        .dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
        #stats {{
            margin-top: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.68em;
            color: #5a6b7a;
            letter-spacing: 1px;
        }}
        #stats .stat-alert {{ color: {alert_color}; }}
        #tooltip {{
            position: absolute;
            background: #0d141b;
            border: 1px solid #1a2a3a;
            border-radius: 4px;
            padding: 7px 12px;
            font-family: 'Courier New', monospace;
            font-size: 0.68em;
            color: #e0e0e0;
            pointer-events: none;
            display: none;
            z-index: 20;
            white-space: nowrap;
            line-height: 1.6;
        }}
        #brand {{
            position: absolute;
            bottom: 24px;
            left: 24px;
            font-family: 'Courier New', monospace;
            font-size: 0.62em;
            color: #1a2a3a;
            letter-spacing: 1px;
            z-index: 10;
            line-height: 1.8;
        }}
        #brand a {{ color: #2a3a4a; text-decoration: none; }}
        #brand a:hover {{ color: #00d4ff; }}
    </style>
</head>
<body>
    <div id="header">
        <h1>FOX-TRACE // SHADOW MAP</h1>
        <p>SSH Trust &amp; Lateral Movement Analysis</p>
        <div id="risk-badge">RISK SCORE: {risk_score}/100 — {risk_label}</div>
        <div id="stats">{n_keys} key(s) &nbsp;·&nbsp; {n_hosts} hosts &nbsp;·&nbsp; <span class="stat-alert">{n_alerts} alert(s)</span></div>
    </div>
    <div id="tooltip"></div>
    <div class="legend">
        <div class="legend-title">Legend</div>
        <div class="legend-item"><span class="legend-tag"><span class="dot" style="background:#00d4ff;box-shadow:0 0 6px #00d4ff66"></span>Local Machine</span></div>
        <div class="legend-item"><span class="legend-tag"><span class="dot" style="background:#40ffaa"></span>Key — encrypted</span></div>
        <div class="legend-item"><span class="legend-tag"><span class="dot" style="background:#ff4d4d;box-shadow:0 0 6px #ff4d4d66"></span>Key — no passphrase</span></div>
        <div class="legend-item"><span class="legend-tag"><span class="dot" style="background:#ff944d"></span>Private host</span></div>
        <div class="legend-item"><span class="legend-tag"><span class="dot" style="background:#ff6633"></span>External host</span></div>
        <div class="legend-item"><span class="legend-tag"><span class="dot" style="background:#7a9fff"></span>Known service</span></div>
        <div class="legend-item"><span class="legend-tag"><span class="dot" style="background:#5a6b7a"></span>Loopback</span></div>
    </div>
    <div id="details"></div>
    <div id="brand">
        Generated {generated}<br>
        <a href="https://shadowfox.se" target="_blank">shadowfox.se</a>
    </div>
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

        function hostColor(d) {{
            if (d.type === "origin") return "#00d4ff";
            if (d.type === "key")    return d.encrypted ? "#40ffaa" : "#ff4d4d";
            if (d.type === "host") {{
                if (d.category === "loopback") return "#5a6b7a";
                if (d.category === "service")  return "#7a9fff";
                if (d.category === "external") return "#ff6633";
                return "#ff944d";
            }}
            return "#999";
        }}

        const sim = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.links).id(d => d.id).distance(d => d.weight > 1 ? 160 : 200))
            .force("charge", d3.forceManyBody().strength(-500))
            .force("center", d3.forceCenter(W / 2, H / 2))
            .force("collide", d3.forceCollide().radius(d => d.radius + 18).strength(0.8));

        const link = g.append("g").selectAll("line")
            .data(data.links).enter().append("line")
            .attr("class","link")
            .style("stroke-width", d => d.weight > 2 ? 2.5 : d.weight > 1 ? 1.8 : 1.2)
            .style("stroke-opacity", d => d.weight > 2 ? 0.55 : d.weight > 1 ? 0.38 : 0.18);

        const node = g.append("g").selectAll("g")
            .data(data.nodes).enter().append("g").attr("class","node")
            .call(d3.drag()
                .on("start", (e,d) => {{ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
                .on("drag",  (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
                .on("end",   (e,d) => {{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}))
            .on("mouseover", (event, d) => {{
                const tip = d3.select("#tooltip");
                let t = "<strong>" + esc(d.label) + "</strong>";
                if (d.type === "key")
                    t += "<br>" + (d.encrypted ? "✓ encrypted" : "✗ no passphrase") + " &nbsp;·&nbsp; blast " + esc(d.blast_radius) + "%";
                if (d.type === "host")
                    t += "<br>" + esc(d.category || "host");
                if (d.type === "origin")
                    t += "<br>risk score: " + esc(d.risk_score) + "/100";
                if (d.alerts && d.alerts.length > 0)
                    t += "<br><span style='color:#ff4d4d'>" + esc(d.alerts.length) + " alert(s)</span>";
                tip.style("display", "block").html(t);
            }})
            .on("mousemove", (event) => {{
                d3.select("#tooltip")
                    .style("left", (event.pageX + 14) + "px")
                    .style("top",  (event.pageY - 36) + "px");
            }})
            .on("mouseout", () => {{ d3.select("#tooltip").style("display", "none"); }})
            .on("click", (event,d) => {{
                const panel = d3.select("#details");
                let h = "<span class='close-btn' onclick='document.getElementById(&quot;details&quot;).style.display=&quot;none&quot;'>✕ close</span>";
                h += "<h3>" + esc(d.type) + "</h3>";
                h += "<div class='row'><span>Label</span><span>" + esc(d.label) + "</span></div>";

                if (d.type === "host") {{
                    h += "<div class='row'><span>Category</span><span>" + esc(d.category || "unknown") + "</span></div>";
                }}
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
                    h += "<div class='alerts-header'>Alerts &amp; Remediations</div>";
                    d.alerts.forEach(a => {{
                        h += "<span class='alert-badge badge-" + esc(a.level) + "'>" + esc(a.level) + "</span>";
                        h += "<div class='alert-msg'>" + esc(a.message) + "</div>";
                        if (a.remediation) {{
                            h += "<div class='alert-fix'>→ " + esc(a.remediation) + "</div>";
                        }}
                    }});
                }}
                panel.style("display","block").html(h);
            }});

        node.append("circle")
            .attr("r", d => d.radius)
            .attr("fill", hostColor)
            .style("filter", d => {{
                if (d.type === "origin")
                    return "drop-shadow(0 0 12px rgba(0,212,255,0.5))";
                const hasHighAlert = d.alerts && d.alerts.some(a => a.level === "HIGH");
                if (hasHighAlert || (d.type === "key" && !d.encrypted))
                    return "drop-shadow(0 0 10px rgba(255,77,77,0.7))";
                if (d.type === "key" && d.blast_radius > 50)
                    return "drop-shadow(0 0 8px rgba(255,170,77,0.5))";
                return "none";
            }});

        // Text background rect for readability
        node.append("rect")
            .attr("x", d => d.radius + 5)
            .attr("y", "-7")
            .attr("height", "14")
            .attr("rx", "2")
            .attr("fill", "#050a0f")
            .attr("fill-opacity", "0.65")
            .attr("width", d => d.label.length * 6.2 + 6);

        node.append("text")
            .attr("dx", d => d.radius + 8)
            .attr("dy", ".35em")
            .attr("fill", d => {{
                if (d.type === "origin") return "#00d4ff";
                if (d.type === "key")    return d.encrypted ? "#40ffaa" : "#ff4d4d";
                return "#8a9baa";
            }})
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
