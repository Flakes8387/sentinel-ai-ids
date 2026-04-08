import time
import requests
from mitmproxy import http

IDS_API_URL = "http://127.0.0.1:8000/api/analyze"

class IDSInterceptor:
    def __init__(self):
        self.connection_history = []
        
    def request(self, flow: http.HTTPFlow) -> None:
        flow.start_time = time.time()

    def response(self, flow: http.HTTPFlow) -> None:
        self._process_flow(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        self._process_flow(flow, is_error=True)

    def _process_flow(self, flow: http.HTTPFlow, is_error=False) -> None:
        end_time = time.time()
        start = getattr(flow, "start_time", end_time)
        duration = end_time - start
        
        host = flow.request.host
        
        # NSL-KDD style 'service' categorizations (e.g. http, ftp, private, etc)
        # We will use the URL path prefix or simply 'http'
        path_parts = flow.request.path.split('?')
        base_path = path_parts[0]
        service = base_path.split('/')[1] if len(base_path.split('/')) > 1 and base_path.split('/')[1] else "http"
        
        # NSL-KDD errors:
        # serror = TCP SYN error / timeout / connect error. We approximate this using bad gateway/timeouts/mitm errors.
        # rerror = TCP reset / rejected / service unavailable. We approximate with 500s or 503s.
        serror = 1 if is_error or (flow.response and flow.response.status_code in [401, 403, 408, 504]) else 0
        rerror = 1 if flow.response and flow.response.status_code in [500, 502, 503] else 0

        # Data sizes
        req_len = len(flow.request.content) if flow.request and flow.request.content else 0
        resp_len = len(flow.response.content) if flow.response and flow.response.content else 0
        
        current_conn = {
            "timestamp": end_time,
            "host": host,
            "service": service,
            "serror": serror,
            "rerror": rerror,
            "duration": duration,
            "src_bytes": req_len,
            "dst_bytes": resp_len
        }
        
        self.connection_history.append(current_conn)
        
        # Keep only last 100 connections for dst_host_* features to prevent memory bloat
        if len(self.connection_history) > 100:
            self.connection_history = self.connection_history[-100:]
            
        # Calculate time-window based features (past 2 seconds)
        two_sec_ago = end_time - 2.0
        window_conns = [c for c in self.connection_history if c["timestamp"] >= two_sec_ago]
        host_window = [c for c in window_conns if c["host"] == host]
        srv_window = [c for c in window_conns if c["service"] == service]
        
        count = len(host_window)
        srv_count = len(srv_window)
        
        serror_rate = sum(c["serror"] for c in host_window) / count if count > 0 else 0.0
        srv_serror_rate = sum(c["serror"] for c in srv_window) / srv_count if srv_count > 0 else 0.0
        rerror_rate = sum(c["rerror"] for c in host_window) / count if count > 0 else 0.0
        
        same_srv_rate = sum(1 for c in host_window if c["service"] == service) / count if count > 0 else 0.0
        diff_srv_rate = 1.0 - same_srv_rate
        
        # Calculate connection-window based features (last 100 historical connections to same dst_host)
        dst_host_conns = [c for c in self.connection_history if c["host"] == host]
        dst_host_count = len(dst_host_conns)
        
        dst_host_srv_conns = [c for c in dst_host_conns if c["service"] == service]
        dst_host_srv_count = len(dst_host_srv_conns)
        
        dst_host_same_srv_rate = dst_host_srv_count / dst_host_count if dst_host_count > 0 else 0.0
        dst_host_diff_srv_rate = 1.0 - dst_host_same_srv_rate
        
        dst_host_serror_rate = sum(c["serror"] for c in dst_host_conns) / dst_host_count if dst_host_count > 0 else 0.0
        dst_host_srv_serror_rate = sum(c["serror"] for c in dst_host_srv_conns) / dst_host_srv_count if dst_host_srv_count > 0 else 0.0
        
        traffic_data = {
            "client_ip": flow.client_conn.address[0],
            "method": flow.request.method,
            "host": host,
            "path": flow.request.path,
            "duration": duration,
            "src_bytes": req_len,
            "dst_bytes": resp_len,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "srv_serror_rate": srv_serror_rate,
            "rerror_rate": rerror_rate,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "dst_host_serror_rate": dst_host_serror_rate,
            "dst_host_srv_serror_rate": dst_host_srv_serror_rate
        }
        
        try:
            requests.post(IDS_API_URL, json=traffic_data, timeout=2.0)
        except requests.exceptions.RequestException:
            pass

addons = [
    IDSInterceptor()
]
