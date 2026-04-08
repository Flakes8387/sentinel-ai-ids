import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import { AlertTriangle, ShieldCheck, Activity, ShieldAlert, Download, Terminal, Map, Server, Lock, CheckCircle } from 'lucide-react';
import ThreatMap from './ThreatMap';
import './index.css';

// Initialize socket connection (fails softly if backend isn't up yet)
const socket = io("http://localhost:8000");

function App() {
  const [alerts, setAlerts] = useState(() => {
    const saved = localStorage.getItem("sentinel_alerts");
    return saved ? JSON.parse(saved) : [];
  });

  const [overallRisk, setOverallRisk] = useState(() => {
    return localStorage.getItem("sentinel_risk_status") || "Nominal";
  });
  const [riskValue, setRiskValue] = useState(() => {
    const saved = localStorage.getItem("sentinel_risk_value");
    return saved ? parseFloat(saved) : 1.2;
  });
  const [isCritical, setIsCritical] = useState(() => {
    const saved = localStorage.getItem("sentinel_is_critical");
    return saved === "true" ? true : false;
  });

  useEffect(() => {
    localStorage.setItem("sentinel_alerts", JSON.stringify(alerts));
    localStorage.setItem("sentinel_risk_status", overallRisk);
    localStorage.setItem("sentinel_risk_value", riskValue.toString());
    localStorage.setItem("sentinel_is_critical", isCritical.toString());
  }, [alerts, overallRisk, riskValue, isCritical]);

  const lastAttackTime = React.useRef(Date.now());
  const [isPaused, setIsPaused] = React.useState(false);
  const [hostFilter, setHostFilter] = React.useState("");

  const handleFeedback = async (clientIp) => {
    if (!clientIp) return;
    try {
      await fetch('http://localhost:8000/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_ip: clientIp, is_safe: true })
      });
      // remove alerts matching IP so it "disappears" 
      setAlerts(prev => prev.filter(a => a.traffic?.client_ip !== clientIp));
    } catch (err) {
      console.error(err);
    }
  };

  const displayAlerts = alerts.filter(a => {
    if (!hostFilter) return true;
    return a.traffic?.host?.includes(hostFilter);
  });

  useEffect(() => {
    // Listen for real-time alerts from the backend
    socket.on('new_alert', (data) => {
      // Short-circuit completely if user clicked 'Pause Stream'
      if (isPaused) return;

      // Log the exact moment the threat arrived
      lastAttackTime.current = Date.now();

      const newLog = {
        ...data,
        timestamp: new Date().toLocaleTimeString()
      };

      setAlerts(prev => [newLog, ...prev].slice(0, 50)); // Keep last 50 logs

      // Update overall risk dynamically based on incoming real alerts
      const currentRisk = data.risk_score || 0;
      if (currentRisk > 0.8) {
        setRiskValue(prev => Math.max(prev, currentRisk * 10)); // Instantly spike scale
        setOverallRisk("Critical Threat");
        setIsCritical(true);
      } else if (currentRisk > 0.5) {
        setRiskValue(prev => Math.max(prev, currentRisk * 10)); // Instantly elevate scale
        setOverallRisk("Elevated");
        setIsCritical(false);
      }
    });

    // Algorithmic Thermal Decay model: smooth mathematical cool-off
    const decayInterval = setInterval(() => {
      setRiskValue(prev => {
        // Only start decaying if there have been NO attacks for the last 10 seconds
        if (Date.now() - lastAttackTime.current < 10000) {
          return prev; // Maintain peak alert state during active combat
        }

        // Apply exponential thermal decay (loses 8% of its remaining severity every tick)
        // This is non-obvious and mathematically models how real-world systems cool off
        const nextVal = Math.max(1.0, prev - (prev * 0.08));

        // Dynamically shift UI labels based on where the math lands
        if (nextVal < 4.0) {
          setOverallRisk("Nominal");
          setIsCritical(false);
        } else if (nextVal < 7.0) {
          setOverallRisk("Elevated");
          setIsCritical(false);
        }

        // Round to 2 decimal places to prevent messy Javascript floating point numbers
        return Math.round(nextVal * 100) / 100;
      });
    }, 4000); // Compute algorithm every 4 seconds

    return () => {
      socket.off('new_alert');
      clearInterval(decayInterval);
    };
  }, [isPaused]);

  return (
    <div style={{ padding: '2rem 3rem', maxWidth: '1600px', margin: '0 auto' }}>

      {/* Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ background: 'var(--accent-base)', padding: '12px', borderRadius: '16px', boxShadow: '0 0 20px var(--accent-glow)' }}>
            <ShieldCheck size={32} color="white" />
          </div>
          <div>
            <h1 style={{ fontSize: '2.5rem', margin: '0 0 0.2rem 0', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              Sentinel <span style={{ color: 'var(--accent-base)' }}>AI</span>
            </h1>
            <p style={{ margin: 0, fontSize: '0.9rem', display: 'flex', alignItems: 'center' }}>
              <span className={`status-indicator ${isPaused ? 'status-paused' : 'status-active'}`} style={{
                background: isPaused ? 'var(--text-secondary)' : 'var(--healthy-base)',
                boxShadow: isPaused ? 'none' : '0 0 10px var(--healthy-glow)'
              }}></span> {isPaused ? 'System Paused' : 'Core ML Engine Active • Real-time Monitoring'}
            </p>
          </div>
        </div>
        <button
          className="glass-btn primary"
          onClick={() => {
            if (alerts.length === 0) {
              alert("No threats detected to export!");
            } else {
              const csvContent = "data:text/csv;charset=utf-8,"
                + "Timestamp,Threat Type,Risk Score,IP,Host,Path\n"
                + alerts.map(a => `${a.timestamp},${a.threat_type},${a.risk_score.toFixed(2)},${a.traffic?.client_ip || ''},${a.traffic?.host || ''},${a.traffic?.path || ''}`).join("\n");
              const encodedUri = encodeURI(csvContent);
              const link = document.createElement("a");
              link.setAttribute("href", encodedUri);
              link.setAttribute("download", `sentinel_threat_report_${new Date().getTime()}.csv`);
              document.body.appendChild(link);
              link.click();
              document.body.removeChild(link);
            }
          }}
        >
          <Download size={18} /> Export Threat Report
        </button>
      </header>

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '2rem' }}>

        {/* Risk Score Card */}
        <div className={`glass-panel ${isCritical ? 'critical' : ''}`} style={{ gridColumn: 'span 4', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}>
          <h3 style={{ alignSelf: 'flex-start', display: 'flex', gap: '8px', alignItems: 'center' }}>
            <Activity size={20} color={isCritical ? 'var(--critical-base)' : 'var(--accent-base)'} />
            Context-Aware Risk Score
          </h3>

          <div style={{ position: 'relative', margin: '2rem 0' }}>
            <div style={{
              width: '160px', height: '160px', borderRadius: '50%',
              border: `6px solid ${isCritical ? 'var(--critical-base)' : 'var(--healthy-base)'}`,
              display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
              boxShadow: `0 0 30px ${isCritical ? 'var(--critical-glow)' : 'var(--healthy-glow)'}`,
              transition: 'all 0.5s ease'
            }}>
              <span style={{ fontSize: '3rem', fontFamily: 'Outfit', fontWeight: '700', lineHeight: '1' }}>
                {riskValue.toFixed(1)}
              </span>
              <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>/ 10</span>
            </div>
          </div>

          <h2 style={{ margin: '0 0 0.5rem 0', color: isCritical ? 'var(--critical-base)' : 'var(--text-primary)' }}>
            Posture: {overallRisk}
          </h2>
          <p style={{ margin: 0, fontSize: '0.85rem' }}>
            Last anomaly detected: {displayAlerts.length > 0 ? displayAlerts[0].timestamp : 'System analyzing...'}
          </p>
        </div>

        {/* Global Threat Map & KPIs */}
        <div style={{ gridColumn: 'span 8', display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          {/* Real Global Threat Map */}
          <div className="glass-panel" style={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
            <h3 style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <Map size={20} color="var(--accent-base)" /> Spatial Telemetry
            </h3>
            <div style={{ flexGrow: 1, background: 'rgba(0,0,0,0.2)', borderRadius: '12px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', border: '1px solid rgba(255,255,255,0.05)', position: 'relative', overflow: 'hidden' }}>
              <ThreatMap isCritical={isCritical} alerts={displayAlerts} />
              <div style={{ position: 'absolute', bottom: '10px', left: '0', width: '100%', textAlign: 'center' }}>
                <p style={{ margin: 0, fontFamily: 'Outfit', fontWeight: '500', fontSize: '0.8rem', background: 'rgba(0,0,0,0.5)', display: 'inline-block', padding: '4px 12px', borderRadius: '20px' }}>Geographical context active. Tracing threat vectors.</p>
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
            <div className="kpi-gauge">
              <span className="kpi-label">Unique Threats</span>
              <span className="kpi-value" style={{ color: 'var(--healthy-base)' }}>
                {new Set(displayAlerts.map(a => a.threat_type)).size}
              </span>
            </div>
            <div className="kpi-gauge">
              <span className="kpi-label">Elevated Events</span>
              <span className="kpi-value">{displayAlerts.filter(a => a.risk_score > 0.5).length}</span>
            </div>
            <div className="kpi-gauge">
              <span className="kpi-label">Inference Latency</span>
              <span className="kpi-value" style={{ color: 'var(--accent-base)' }}>
                {displayAlerts.length > 0 && displayAlerts[0].latency_ms ? `${displayAlerts[0].latency_ms}ms` : '0ms'}
              </span>
            </div>
          </div>
        </div>

        {/* Real-Time Logs */}
        <div className="glass-panel" style={{ gridColumn: 'span 12' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
            <h3 style={{ margin: 0, display: 'flex', gap: '8px', alignItems: 'center' }}>
              <Terminal size={20} color="var(--accent-base)" /> Hybrid AE-RF Security Event Log
            </h3>
            <div style={{ display: 'flex', gap: '8px' }}>
              <div style={{ position: 'relative' }}>
                <Server size={14} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-secondary)' }} />
                <input
                  type="text"
                  placeholder="Filter by Host IP..."
                  className="glass-btn"
                  style={{ paddingLeft: '30px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.1)', color: 'white' }}
                  value={hostFilter}
                  onChange={(e) => setHostFilter(e.target.value)}
                />
              </div>
              <button
                className="glass-btn"
                onClick={() => setIsPaused(!isPaused)}
                style={{ background: isPaused ? 'rgba(255, 68, 68, 0.2)' : '' }}
              >
                <Lock size={14} /> {isPaused ? 'Resume Stream' : 'Pause Stream'}
              </button>
            </div>
          </div>

          <div className="log-feed">
            {displayAlerts.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '3rem 0', color: 'var(--text-secondary)' }}>
                <Activity size={32} opacity={0.5} style={{ marginBottom: '1rem' }} />
                <p>{hostFilter ? 'No alerts match criteria' : 'Awaiting network telemetry...'}</p>
              </div>
            ) : (
              displayAlerts.map((alert, i) => (
                <div key={i} className="log-item" style={{ borderLeft: `3px solid ${alert.is_anomaly ? 'var(--critical-base)' : 'var(--healthy-base)'}` }}>
                  <div className="log-icon" style={{ background: alert.is_anomaly ? 'rgba(251, 113, 133, 0.1)' : 'rgba(52, 211, 153, 0.1)' }}>
                    {alert.is_anomaly ? <AlertTriangle size={20} color="var(--critical-base)" /> : <ShieldCheck size={20} color="var(--healthy-base)" />}
                  </div>
                  <div style={{ flexGrow: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <strong style={{ color: alert.is_anomaly ? 'var(--critical-base)' : 'var(--text-primary)', fontFamily: 'Outfit' }}>
                        {alert.threat_type} detected
                      </strong>
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {alert.timestamp || 'Just now'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: '1rem', fontSize: '0.85rem' }}>
                      <span><strong>Host Target:</strong> <code style={{ color: 'var(--accent-base)' }}>{alert.traffic?.host || 'Unknown'}</code></span>
                      <span><strong>Method:</strong> {alert.traffic?.method || 'GET'}</span>
                      <span><strong>Path:</strong> {alert.traffic?.path || '/'}</span>
                    </div>
                  </div>
                  {alert.is_anomaly && alert.explanations && alert.explanations.length > 0 && (
                    <div style={{ marginTop: '8px', padding: '6px 10px', background: 'rgba(251, 113, 133, 0.05)', borderRadius: '4px', borderLeft: '2px solid rgba(251, 113, 133, 0.5)' }}>
                      <strong style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--critical-base)' }}>Explainability Engine:</strong>
                      <ul style={{ margin: '4px 0 0 0', paddingLeft: '1.2rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {alert.explanations.map((exp, idx) => (
                          <li key={idx} style={{ marginBottom: '2px' }}>{exp}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {alert.is_anomaly && (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', marginLeft: 'auto', gap: '8px' }}>
                      <div style={{ textAlign: 'right' }}>
                        <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-secondary)', display: 'block' }}>CARS Score</span>
                        <strong style={{ fontFamily: 'Outfit', fontSize: '1.2rem', color: 'var(--critical-base)' }}>{(alert.risk_score * 10).toFixed(1)}</strong>
                      </div>
                      <button
                        className="glass-btn"
                        onClick={() => handleFeedback(alert.traffic?.client_ip)}
                        style={{ padding: '4px 8px', fontSize: '0.75rem', background: 'rgba(52, 211, 153, 0.1)', color: 'var(--healthy-base)', border: '1px solid rgba(52, 211, 153, 0.3)' }}
                        title="Mark as Safe / Retrain Model"
                      >
                        <CheckCircle size={12} style={{ marginRight: '4px' }} /> Mark Safe
                      </button>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

      </div>
    </div>
  );
}

export default App;
