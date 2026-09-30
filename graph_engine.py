from typing import List, Dict, Any

class ForensicGraphEngine:
    """
    Step 3: Knowledge Graph Engine (Vis.js / Cytoscape compatible).
    Generates causal node-link relationships linking Users, Processes, Files, IPs, and Devices.
    """
    
    def build_graph(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        nodes = []
        edges = []
        node_map = {}
        
        def add_node(node_id: str, label: str, group: str, shape: str = "dot", color: str = "#3b82f6", detail: str = ""):
            if node_id not in node_map:
                node_obj = {
                    "id": node_id,
                    "label": label,
                    "group": group,
                    "shape": shape,
                    "color": color,
                    "title": detail or label
                }
                nodes.append(node_obj)
                node_map[node_id] = node_obj

        def add_edge(source: str, target: str, label: str, color: str = "#94a3b8"):
            edges.append({
                "from": source,
                "to": target,
                "label": label,
                "color": {"color": color, "highlight": "#ef4444"},
                "arrows": "to",
                "font": {"size": 11, "color": "#cbd5e1", "align": "horizontal"}
            })

        # Base Host Node
        add_node("HOST_01", "WORKSTATION-RIG-01\n(192.168.1.105)", "HOST", "box", "#06b6d4", "Target Forensic Host Workstation")
        
        for ev in events:
            ev_id = ev["event_id"]
            ev_label = f"[{ev['event_id']}]\n{ev.get('category', 'EVENT')}"
            
            # Event Node
            risk_color = "#ef4444" if ev.get("risk_score") == "CRITICAL" else ("#f59e0b" if ev.get("risk_score") == "HIGH" else "#3b82f6")
            add_node(ev_id, ev_label, "EVENT", "diamond", risk_color, f"Timestamp: {ev['timestamp_utc']}\n{ev['description']}")
            
            # Link Host to Event
            add_edge("HOST_01", ev_id, "TRIGGERED", "#475569")

            # Extract User Entity
            if "user" in ev:
                user_id = f"USER_{ev['user']}"
                add_node(user_id, f"User: {ev['user']}", "USER", "ellipse", "#a855f7", "Investigated User Account")
                add_edge(user_id, ev_id, "INITIATED", "#c084fc")

            # Extract Process Entity
            if "process_name" in ev:
                proc_id = f"PROC_{ev['process_name']}"
                add_node(proc_id, f"Process:\n{ev['process_name']}", "PROCESS", "ellipse", "#ec4899", f"Cmd: {ev.get('command_line', ev['process_name'])}")
                add_edge(ev_id, proc_id, "SPAWNED", "#f472b6")

            # Extract USB/Device Entity
            if "device" in ev:
                dev_id = f"DEV_{ev['device'].replace(' ', '_')}"
                add_node(dev_id, f"Device:\n{ev['device']}", "HARDWARE", "database", "#10b981", f"Serial: {ev.get('serial_number', 'N/A')}")
                add_edge(ev_id, dev_id, "ATTACHED", "#34d399")

            # Extract File Entity
            if "file_path" in ev or "dest_path" in ev:
                f_name = ev.get("dest_path", ev.get("file_path", "file.tmp")).split("\\")[-1]
                f_id = f"FILE_{f_name}"
                add_node(f_id, f"File:\n{f_name}", "FILE", "star", "#f59e0b", f"Path: {ev.get('dest_path', ev.get('file_path'))}")
                add_edge(ev_id, f_id, "COPIED_TO", "#fbbf24")

            # Extract IP / C2 Domain
            if "dest_ip" in ev or "domain" in ev:
                ip_val = ev.get("dest_ip", ev.get("domain"))
                ip_id = f"NET_{ip_val}"
                add_node(ip_id, f"C2 Domain/IP:\n{ip_val}", "NETWORK", "triangle", "#ef4444", f"Protocol: {ev.get('protocol', 'TCP')}")
                add_edge(ev_id, ip_id, "BEACONED", "#f87171")

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges)
        }
