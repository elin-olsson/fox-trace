import json
import os
import webbrowser

class FoxVisualizer:
    def __init__(self, data_path="data/findings.json"):
        self.data_path = data_path
        self.output_path = "data/shadow_map.html"

    def _prepare_graph_data(self, data):
        nodes = [{"id": "localhost", "label": "Local Machine", "type": "origin"}]
        links = []

        # Add Keys as nodes and link to localhost
        for key in data.get("public_keys", []):
            key_id = f"key_{key['fingerprint']}"
            nodes.append({
                "id": key_id, 
                "label": f"Key: {key['name']}", 
                "type": "key",
                "comment": key.get("comment", "")
            })
            links.append({"source": "localhost", "target": key_id})

        # Add Known Hosts and link from localhost
        for host in data.get("known_hosts", []):
            host_id = f"host_{host['host']}"
            if not any(n['id'] == host_id for n in nodes):
                nodes.append({
                    "id": host_id, 
                    "label": host['host'], 
                    "type": "host",
                    "is_hashed": host.get("is_hashed", False)
                })
            links.append({"source": "localhost", "target": host_id})

        # Add Risk Alerts as nodes
        for i, alert in enumerate(data.get("risk_alerts", [])):
            alert_id = f"alert_{i}"
            nodes.append({"id": alert_id, "label": alert['level'], "type": "alert", "msg": alert['message']})
            links.append({"source": "localhost", "target": alert_id})

        return {"nodes": nodes, "links": links}

    def generate(self):
        if not os.path.exists(self.data_path):
            print(f"Error: {self.data_path} not found.")
            return False

        with open(self.data_path, "r") as f:
            raw_data = json.load(f)

        graph_data = self._prepare_graph_data(raw_data)
        
        if len(graph_data["nodes"]) <= 1:
            print("[!] No data found to visualize. Run the harvester first.")
            return False

        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Fox-trace | Shadow Map</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{ 
            background-color: #050a0f; 
            color: #00d4ff; 
            font-family: 'Segoe UI', Tahoma, sans-serif; 
            margin: 0; 
            overflow: hidden;
        }}
        .node circle {{ stroke: #1a2a3a; stroke-width: 2px; }}
        .node text {{ fill: #e0e0e0; font-size: 11px; pointer-events: none; }}
        .link {{ stroke: #1a2a3a; stroke-opacity: 0.4; stroke-width: 1px; }}
        #header {{ position: absolute; top: 20px; left: 20px; z-index: 10; }}
        #header h1 {{ font-family: 'Courier New', monospace; letter-spacing: 2px; margin: 0; }}
        #header p {{ font-size: 0.8em; color: #5a6b7a; margin: 5px 0 0 0; }}
        #details {{ 
            position: absolute; bottom: 20px; right: 20px; 
            background: rgba(13, 20, 27, 0.95); padding: 15px; 
            border: 1px solid #1a2a3a; border-radius: 8px;
            width: 320px; display: none; z-index: 10;
            box-shadow: 0 4px 15px rgba(0,0,0,0.5);
        }}
        .legend {{ position: absolute; top: 20px; right: 20px; font-size: 12px; z-index: 10; }}
        .legend-item {{ display: flex; align-items: center; margin-bottom: 5px; color: #8a9baa; }}
        .dot {{ width: 10px; height: 10px; border-radius: 50%; margin-right: 10px; }}
    </style>
</head>
<body>
    <div id="header">
        <h1>FOX-TRACE // SHADOW MAP</h1>
        <p>SSH Trust & Lateral Movement Paths</p>
    </div>

    <div class="legend">
        <div class="legend-item"><div class="dot" style="background: #00d4ff;"></div> Local Machine</div>
        <div class="legend-item"><div class="dot" style="background: #40ffaa;"></div> SSH Keys</div>
        <div class="legend-item"><div class="dot" style="background: #ff944d;"></div> Known Hosts</div>
        <div class="legend-item"><div class="dot" style="background: #ff4d4d;"></div> Risks/Alerts</div>
    </div>

    <div id="details"></div>

    <script>
        const data = {json.dumps(graph_data)};
        const width = window.innerWidth;
        const height = window.innerHeight;

        const svg = d3.select("body").append("svg")
            .attr("width", width)
            .attr("height", height);

        // Zoom and Pan support
        svg.call(d3.zoom().on("zoom", (event) => {{
            g.attr("transform", event.transform);
        }}));

        const g = svg.append("g");

        const simulation = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.links).id(d => d.id).distance(180))
            .force("charge", d3.forceManyBody().strength(-400))
            .force("center", d3.forceCenter(width / 2, height / 2));

        const link = g.append("g")
            .attr("class", "links")
            .selectAll("line")
            .data(data.links)
            .enter().append("line")
            .attr("class", "link");

        const node = g.append("g")
            .attr("class", "nodes")
            .selectAll("g")
            .data(data.nodes)
            .enter().append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended))
            .on("click", (event, d) => {{
                const details = d3.select("#details");
                details.style("display", "block")
                    .html("<h3 style='margin:0 0 10px 0; color:#00d4ff'>" + d.type.toUpperCase() + "</h3>" +
                          "<strong>Label:</strong> " + d.label + "<br>" + 
                          "<strong>ID:</strong> <code style='font-size:0.9em'>" + d.id + "</code>" + 
                          (d.msg ? "<br><br><span style='color:#ff4d4d'><strong>ALERT:</strong> " + d.msg + "</span>" : ""));
            }});

        node.append("circle")
            .attr("r", 12)
            .attr("fill", d => {{
                if (d.type === "origin") return "#00d4ff";
                if (d.type === "key") return "#40ffaa";
                if (d.type === "host") return "#ff944d";
                if (d.type === "alert") return "#ff4d4d";
                return "#999";
            }})
            .style("filter", "drop-shadow(0 0 5px rgba(0,212,255,0.3))");

        node.append("text")
            .attr("dx", 18)
            .attr("dy", ".35em")
            .text(d => d.label);

        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node
                .attr("transform", d => "translate(" + d.x + "," + d.y + ")");
        }});

        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}

        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}

        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
    </script>
</body>
</html>
"""
        with open(self.output_path, "w") as f:
            f.write(html_template)
        
        print(f"\n[SUCCESS] Shadow Map generated: {self.output_path}")
        
        # Automatically open in browser
        try:
            full_path = "file://" + os.path.abspath(self.output_path)
            webbrowser.open(full_path)
        except Exception:
            print("[!] Could not open browser automatically. Please open data/shadow_map.html manually.")
            
        return True

if __name__ == "__main__":
    visualizer = FoxVisualizer()
    visualizer.generate()
