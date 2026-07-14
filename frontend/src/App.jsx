import React, { useState, useEffect, useMemo } from 'react';
import { 
  ShieldAlert, 
  Upload, 
  Activity, 
  TrendingUp, 
  Users, 
  BarChart3, 
  PieChart as PieIcon, 
  FileText, 
  Filter, 
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Search,
  X,
  Download
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  LineChart,
  Line,
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  AreaChart, 
  Area,
  PieChart,
  Cell,
  Pie
} from 'recharts';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || '/api';

const DestinationIPCell = ({ dstIp }) => {
  const [expanded, setExpanded] = useState(false);

  if (!dstIp) return <span style={{ color: 'var(--text-muted)' }}>-</span>;

  // Split by comma
  const ips = dstIp.split(',').map(ip => ip.trim()).filter(Boolean);

  if (ips.length <= 1) {
    return <span style={{ fontFamily: 'monospace' }}>{dstIp}</span>;
  }

  if (expanded) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', minWidth: '180px' }}>
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '0.25rem',
          maxHeight: '110px',
          overflowY: 'auto',
          padding: '2px',
          backgroundColor: 'rgba(0, 0, 0, 0.2)',
          borderRadius: '4px',
          border: '1px solid var(--border-color)'
        }}>
          {ips.map((ip, idx) => (
            <span key={idx} style={{
              fontFamily: 'monospace',
              fontSize: '0.75rem',
              padding: '0.1rem 0.35rem',
              background: 'rgba(255,255,255,0.06)',
              border: '1px solid rgba(255,255,255,0.04)',
              borderRadius: '4px',
              color: 'var(--text-primary)'
            }}>{ip}</span>
          ))}
        </div>
        <button
          onClick={(e) => { e.stopPropagation(); setExpanded(false); }}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--accent-blue)',
            cursor: 'pointer',
            fontSize: '0.75rem',
            textAlign: 'left',
            padding: 0,
            width: 'fit-content',
            textDecoration: 'underline'
          }}
        >
          Show less
        </button>
      </div>
    );
  }

  const visibleIps = ips.slice(0, 3);
  const remaining = ips.length - 3;

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.25rem', minWidth: '180px' }}>
      {visibleIps.map((ip, idx) => (
        <span key={idx} style={{
          fontFamily: 'monospace',
          fontSize: '0.75rem',
          padding: '0.1rem 0.35rem',
          background: 'rgba(255,255,255,0.06)',
          border: '1px solid rgba(255,255,255,0.04)',
          borderRadius: '4px',
          color: 'var(--text-primary)'
        }}>{ip}</span>
      ))}
      {remaining > 0 && (
        <button
          onClick={(e) => { e.stopPropagation(); setExpanded(true); }}
          style={{
            background: 'rgba(59, 130, 246, 0.15)',
            border: '1px solid rgba(59, 130, 246, 0.25)',
            color: '#60a5fa',
            borderRadius: '4px',
            fontSize: '0.7rem',
            padding: '0.1rem 0.35rem',
            cursor: 'pointer',
            fontWeight: 600,
            display: 'inline-flex',
            alignItems: 'center',
            transition: 'background 0.2s',
          }}
          onMouseEnter={(e) => e.target.style.backgroundColor = 'rgba(59, 130, 246, 0.25)'}
          onMouseLeave={(e) => e.target.style.backgroundColor = 'rgba(59, 130, 246, 0.15)'}
        >
          +{remaining} more
        </button>
      )}
    </div>
  );
};

function App() {
  const [stats, setStats] = useState(null);
  const [charts, setCharts] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(null);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  
  // Filters state
  const [severityFilter, setSeverityFilter] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('');
  const [threatTypeFilter, setThreatTypeFilter] = useState('');
  const [ipSearch, setIpSearch] = useState('');

  // Fetch stats and alerts on load
  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const statsRes = await fetch(`${BACKEND_URL}/stats`);
      if (!statsRes.ok) throw new Error("Backend not reachable");
      const statsData = await statsRes.json();
      
      setStats(statsData.stats);
      setCharts(statsData.charts);

      // Get alerts
      const alertsRes = await fetch(`${BACKEND_URL}/alerts`);
      const alertsData = await alertsRes.json();
      setAlerts(alertsData);
      setError(null);
    } catch (err) {
      console.error(err);
      setError("Unable to connect to the backend threat engine. Please ensure the FastAPI server is running on port 8000.");
    }
  };

  // Drag and drop handlers
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      await uploadFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = async (e) => {
    if (e.target.files && e.target.files[0]) {
      await uploadFile(e.target.files[0]);
    }
  };

  const uploadFile = async (file) => {
    if (!file.name.endsWith('.csv')) {
      setError("Invalid file format. Please upload a CSV NetFlow file.");
      return;
    }

    setLoading(true);
    setUploadProgress("Ingesting NetFlow data...");
    setError(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      setUploadProgress("Feature engineering & processing...");
      const res = await fetch(`${BACKEND_URL}/upload`, {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.detail || "Failed to process NetFlow file.");
      }

      setUploadProgress("Analyzing threats with parallel Rule Engine & PyOD Isolation Forest...");
      
      // Wait a short bit to show the complete phase transitions
      await new Promise(resolve => setTimeout(resolve, 800));
      
      await fetchData();
    } catch (err) {
      console.error(err);
      setError(err.message || "An error occurred during file upload.");
    } finally {
      setLoading(false);
      setUploadProgress(null);
    }
  };

  // Filter alerts locally for maximum speed and smooth interaction
  const filteredAlerts = alerts.filter(alert => {
    const matchSeverity = severityFilter === '' || (alert.severity || '').toLowerCase() === severityFilter.toLowerCase();
    const matchProtocol = protocolFilter === '' || (alert.protocol || '').toString().toUpperCase() === protocolFilter.toUpperCase();
    const matchThreatType = threatTypeFilter === '' || (alert.threat_type || '') === threatTypeFilter;
    const matchIP = ipSearch === '' ||
      (alert.src_ip || '').includes(ipSearch.trim()) ||
      (alert.dst_ip || '').includes(ipSearch.trim());
    return matchSeverity && matchProtocol && matchThreatType && matchIP;
  });

  // Extract unique protocols from current alerts for sidebar filter dropdown dynamically
  const uniqueProtocols = Array.from(
    new Set(alerts.map(a => (a.protocol || '').toString().toUpperCase()).filter(Boolean))
  );

  // Extract unique threat types from current alerts
  const uniqueThreatTypes = Array.from(
    new Set(alerts.map(a => a.threat_type).filter(Boolean))
  );

  // Derive charts from filteredAlerts so all filters affect both charts
  const isFiltered = severityFilter !== '' || protocolFilter !== '' || threatTypeFilter !== '' || ipSearch !== '';

  const filteredHistogram = useMemo(() => {
    if (!isFiltered) return charts?.histogram || [];
    const bins = Array.from({ length: 20 }, (_, i) => ({
      bin_start: parseFloat((i * 0.05).toFixed(2)),
      bin_end: parseFloat(((i + 1) * 0.05).toFixed(2)),
      count: 0
    }));
    filteredAlerts.forEach(a => {
      const idx = Math.min(Math.floor((a.confidence || 0) / 0.05), 19);
      bins[idx].count++;
    });
    return bins;
  }, [filteredAlerts, isFiltered, charts]);

  const filteredTimeline = useMemo(() => {
    if (!isFiltered) return charts?.threats_over_time || [];
    const ratio = alerts.length > 0 ? filteredAlerts.length / alerts.length : 0;
    return (charts?.threats_over_time || []).map(bin => ({
      ...bin,
      threat_count: Math.round(bin.threat_count * ratio)
    }));
  }, [filteredAlerts, isFiltered, charts, alerts.length]);

  // Export currently visible (filtered) alerts as CSV
  const exportCSV = () => {
    if (filteredAlerts.length === 0) return;
    const headers = ['src_ip', 'dst_ip', 'protocol', 'threat_type', 'flows', 'confidence', 'severity', 'evidence'];
    const rows = filteredAlerts.map(a =>
      headers.map(h => {
        const key = h === 'flows' ? 'flow_count' : h;
        const val = key === 'confidence' ? `${Math.round((a[key] || 0) * 100)}%` : (a[key] ?? '');
        return `"${String(val).replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netflow_alerts_${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Pie chart colors for protocol distribution
  const PIE_COLORS = ['#8b5cf6', '#3b82f6', '#0d9488', '#f59e0b', '#ef4444', '#10b981'];

  // Format stats numbers with commas
  const formatNum = (num) => num ? num.toLocaleString() : '0';

  return (
    <div className="app-container">
      {/* Sidebar Filters */}
      <aside className="sidebar">
        <div className="brand">
          <ShieldAlert className="brand-icon" size={28} />
          <span className="brand-title">NetFlow Shield</span>
        </div>

        <div className="sidebar-section">
          <span className="sidebar-title">Filters</span>
          
          <div className="filter-group">
            <label className="filter-label">Severity</label>
            <select 
              className="filter-select"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="confirmed">🔴 Confirmed</option>
              <option value="suspicious">🟡 Suspicious</option>
              <option value="monitor">🔵 Monitor</option>
            </select>
          </div>

          <div className="filter-group">
            <label className="filter-label">Protocol</label>
            <select 
              className="filter-select"
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
            >
              <option value="">All Protocols</option>
              {uniqueProtocols.map(proto => (
                <option key={proto} value={proto}>{proto}</option>
              ))}
              {stats?.protocol_distribution && Object.keys(stats.protocol_distribution).map(proto => {
                const protoUpper = proto.toUpperCase();
                if (!uniqueProtocols.includes(protoUpper)) {
                  return <option key={protoUpper} value={protoUpper}>{protoUpper}</option>;
                }
                return null;
              })}
            </select>
          </div>

          <div className="filter-group">
            <label className="filter-label">Threat Type</label>
            <select 
              className="filter-select"
              value={threatTypeFilter}
              onChange={(e) => setThreatTypeFilter(e.target.value)}
            >
              <option value="">All Threat Types</option>
              {uniqueThreatTypes.map(tt => (
                <option key={tt} value={tt}>{tt}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="sidebar-section" style={{ marginTop: 'auto' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Lock size={12} />
              <span>In-memory sandbox</span>
            </div>
            <div>FastAPI + Polars Engine</div>
            <div>PyOD IsolationForest</div>
          </div>
        </div>
      </aside>

      {/* Main Panel */}
      <main className="dashboard-main animate-fade-in">
        
        {/* Header */}
        <header className="dashboard-header">
          <div className="header-title-section">
            <h1>Threat Analytics Center</h1>
            <p>Real-time NetFlow ingestion, machine learning anomaly detection, and heuristic rule arbitration.</p>
          </div>
          <button 
            onClick={fetchData} 
            className="filter-select" 
            style={{ width: 'auto', display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 1rem' }}
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            <span>Refresh</span>
          </button>
        </header>

        {/* Error alert if any */}
        {error && (
          <div style={{ 
            backgroundColor: 'rgba(239, 68, 68, 0.1)', 
            border: '1px solid rgba(239, 68, 68, 0.2)', 
            borderRadius: '0.75rem', 
            padding: '1rem 1.25rem', 
            color: '#f87171',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            fontSize: '0.875rem'
          }}>
            <AlertTriangle size={18} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {/* Drag & Drop File Upload zone */}
        <div 
          className={`upload-zone ${dragActive ? 'dragging' : ''}`}
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          onClick={() => document.getElementById('netflow-file-input').click()}
        >
          <input 
            type="file" 
            id="netflow-file-input" 
            style={{ display: 'none' }} 
            accept=".csv"
            onChange={handleFileChange}
            disabled={loading}
          />
          <Upload className="upload-icon" size={48} />
          
          {loading ? (
            <div className="progress-container">
              <p className="upload-text">{uploadProgress}</p>
              <div className="progress-bar-bg">
                <div className="progress-bar" style={{ width: '100%', animation: 'pulse 1.5s infinite' }}></div>
              </div>
              <span className="progress-subtext" style={{ marginTop: '0.5rem', display: 'inline-block' }}>Processing 1,000,000+ flows may take a few seconds</span>
            </div>
          ) : (
            <div>
              <p className="upload-text">Drag & drop your NetFlow CSV here or click to browse</p>
              <p className="upload-subtext">Supports large csv files up to 1,000,000 rows. Required headers: src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, flows, start_time, end_time</p>
            </div>
          )}
        </div>

        {/* Dashboard Grid and Content when loaded */}
        {stats ? (
          <>
            {/* Metrics cards */}
            <section className="metrics-grid">
              <div className="metric-card">
                <div className="metric-icon-wrapper">
                  <Activity size={24} style={{ color: 'var(--accent-blue)' }} />
                </div>
                <div className="metric-info">
                  <span className="metric-value">{formatNum(stats.total_flows)}</span>
                  <span className="metric-label">Total Flows Ingested</span>
                </div>
              </div>

              <div className="metric-card">
                <div className="metric-icon-wrapper">
                  <ShieldAlert size={24} style={{ color: stats.threats_detected > 0 ? 'var(--severity-high)' : 'var(--severity-low)' }} />
                </div>
                <div className="metric-info">
                  <span className="metric-value" style={{ color: stats.threats_detected > 0 ? 'var(--severity-high)' : 'inherit' }}>
                    {formatNum(stats.threats_detected)}
                  </span>
                  <span className="metric-label">Threats Detected</span>
                </div>
              </div>

              <div className="metric-card">
                <div className="metric-icon-wrapper">
                  <Users size={24} style={{ color: 'var(--severity-medium)' }} />
                </div>
                <div className="metric-info">
                  <span className="metric-value" style={{ fontSize: stats.top_attacker_ip.length > 15 ? '1.15rem' : '1.5rem' }}>
                    {stats.top_attacker_ip}
                  </span>
                  <span className="metric-label">Top Threat Origin ({stats.top_attacker_count} flows)</span>
                </div>
              </div>

              <div className="metric-card">
                <div className="metric-icon-wrapper">
                  <ShieldAlert size={24} style={{ color: 'var(--accent-purple)' }} />
                </div>
                <div className="metric-info">
                  <span className="metric-value" style={{ fontSize: (stats.top_threat_type || '').length > 15 ? '1.15rem' : '1.5rem' }}>
                    {stats.top_threat_type || 'N/A'}
                  </span>
                  <span className="metric-label">Primary Threat Category ({stats.top_threat_count || 0} flows)</span>
                </div>
              </div>

              <div className="metric-card">
                <div className="metric-icon-wrapper">
                  <TrendingUp size={24} style={{ color: 'var(--accent-teal)' }} />
                </div>
                <div className="metric-info">
                  <span className="metric-value">{stats.processing_time_sec}s</span>
                  <span className="metric-label">Total Execution Time</span>
                </div>
              </div>
            </section>

            {/* Charts Grid */}
            <section className="charts-grid">
              {/* Histogram Anomaly score */}
              <div className="chart-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <BarChart3 size={18} style={{ color: 'var(--accent-purple)' }} />
                  <span className="chart-title">ML Anomaly Score Distribution</span>
                </div>
                <div style={{ flexGrow: 1, minHeight: 300 }}>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={filteredHistogram} margin={{ top: 20, right: 10, left: -10, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                      <XAxis 
                        dataKey="bin_start" 
                        stroke="var(--text-muted)" 
                        fontSize={11} 
                        tickLine={false} 
                      />
                      <YAxis 
                        stroke="var(--text-muted)" 
                        fontSize={11} 
                        tickLine={false} 
                        axisLine={false} 
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: 'var(--bg-secondary)', 
                          borderColor: 'var(--border-color)',
                          borderRadius: '8px',
                          color: 'var(--text-primary)'
                        }} 
                      />
                      <Bar 
                        dataKey="count" 
                        fill="url(#purpleGradient)" 
                        radius={[4, 4, 0, 0]}
                      />
                      <defs>
                        <linearGradient id="purpleGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--accent-purple)" stopOpacity={0.8}/>
                          <stop offset="100%" stopColor="var(--accent-purple)" stopOpacity={0.1}/>
                        </linearGradient>
                      </defs>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Line threats over time */}
              <div className="chart-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Activity size={18} style={{ color: 'var(--accent-blue)' }} />
                  <span className="chart-title">Threat Incidence Timeline</span>
                </div>
                <div style={{ flexGrow: 1, minHeight: 300 }}>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={filteredTimeline} margin={{ top: 20, right: 10, left: -10, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                      <XAxis 
                        dataKey="time" 
                        stroke="var(--text-muted)" 
                        fontSize={10} 
                        tickLine={false} 
                      />
                      <YAxis 
                        stroke="var(--text-muted)" 
                        fontSize={11} 
                        tickLine={false} 
                        axisLine={false} 
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: 'var(--bg-secondary)', 
                          borderColor: 'var(--border-color)',
                          borderRadius: '8px',
                          color: 'var(--text-primary)'
                        }} 
                      />
                      <Area 
                        type="monotone" 
                        dataKey="threat_count" 
                        stroke="var(--accent-blue)" 
                        strokeWidth={2}
                        fillOpacity={1} 
                        fill="url(#blueGradient)" 
                      />
                      <defs>
                        <linearGradient id="blueGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--accent-blue)" stopOpacity={0.4}/>
                          <stop offset="100%" stopColor="var(--accent-blue)" stopOpacity={0.0}/>
                        </linearGradient>
                      </defs>
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </section>

            {/* Protocol Distribution & Extra stats */}
            <section className="charts-grid" style={{ gridTemplateColumns: '1fr 2fr' }}>
              <div className="chart-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <PieIcon size={18} style={{ color: 'var(--accent-teal)' }} />
                  <span className="chart-title">Protocol Split</span>
                </div>
                <div style={{ flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 220 }}>
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie
                        data={Object.entries(stats.protocol_distribution).map(([name, value]) => ({ name, value }))}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={3}
                        dataKey="value"
                      >
                        {Object.entries(stats.protocol_distribution).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: 'var(--bg-secondary)', 
                          borderColor: 'var(--border-color)',
                          borderRadius: '8px',
                          color: 'var(--text-primary)'
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', justifyContent: 'center', fontSize: '0.75rem' }}>
                  {Object.entries(stats.protocol_distribution).map(([proto, count], i) => (
                    <div key={proto} style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <div style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: PIE_COLORS[i % PIE_COLORS.length] }}></div>
                      <span style={{ color: 'var(--text-secondary)' }}>{proto}:</span>
                      <span style={{ fontWeight: 600 }}>{formatNum(count)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Quick Threat Info Card */}
              <div className="chart-card" style={{ justifyContent: 'center', padding: '2rem' }}>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.75rem', color: 'var(--accent-purple)' }}>
                  In-Memory Analytics & ML Arbitration
                </h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.925rem', marginBottom: '1rem', lineHeight: '1.6' }}>
                  The backend uses high-speed <strong style={{ color: '#fff' }}>Polars</strong> dataframes to ingest NetFlow records, engineering per-packet bytes, packets/sec, and network flag indicators in milliseconds.
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.85rem' }}>
                  <div style={{ borderLeft: '3px solid var(--accent-purple)', paddingLeft: '0.75rem' }}>
                    <h4 style={{ fontWeight: 600, color: 'var(--text-primary)' }}>PyOD Isolation Forest</h4>
                    <p style={{ color: 'var(--text-muted)' }}>Identifies multi-dimensional traffic anomalies using unsupervised tree isolation trained dynamically on a sample distribution.</p>
                  </div>
                  <div style={{ borderLeft: '3px solid var(--accent-teal)', paddingLeft: '0.75rem' }}>
                    <h4 style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Rule Engine</h4>
                    <p style={{ color: 'var(--text-muted)' }}>Applies precise high-throughput checks for well-known behaviors like DDoS floods, exfiltration, and brute-force scans.</p>
                  </div>
                </div>
              </div>
            </section>

            {/* Alert List Table */}
            <section className="alerts-section">
              <div className="alerts-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <ShieldAlert size={20} style={{ color: 'var(--severity-high)' }} />
                  <h2 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Correlated Threat Alerts</h2>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div className="alerts-count">
                    Showing {filteredAlerts.length} of {alerts.length} aggregated alerts
                  </div>
                  <button
                    onClick={exportCSV}
                    disabled={filteredAlerts.length === 0}
                    title="Export visible alerts as CSV"
                    style={{
                      display: 'flex', alignItems: 'center', gap: '0.4rem',
                      padding: '0.4rem 0.85rem',
                      backgroundColor: filteredAlerts.length === 0 ? 'var(--bg-secondary)' : 'var(--accent-blue)',
                      color: filteredAlerts.length === 0 ? 'var(--text-muted)' : '#fff',
                      border: 'none', borderRadius: '0.4rem',
                      fontSize: '0.8rem', fontWeight: 600,
                      cursor: filteredAlerts.length === 0 ? 'not-allowed' : 'pointer',
                      transition: 'opacity 0.2s',
                      opacity: filteredAlerts.length === 0 ? 0.5 : 1,
                    }}
                  >
                    <Download size={13} />
                    Export CSV
                  </button>
                </div>
              </div>

              {/* IP Search Bar */}
              <div style={{ position: 'relative', marginBottom: '1rem' }}>
                <Search size={15} style={{
                  position: 'absolute', left: '0.85rem', top: '50%',
                  transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none'
                }} />
                <input
                  type="text"
                  placeholder="Search by source or destination IP..."
                  value={ipSearch}
                  onChange={e => setIpSearch(e.target.value)}
                  style={{
                    width: '100%', boxSizing: 'border-box',
                    padding: '0.6rem 2.5rem 0.6rem 2.25rem',
                    backgroundColor: 'var(--bg-secondary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '0.5rem',
                    color: 'var(--text-primary)',
                    fontSize: '0.875rem', outline: 'none',
                    transition: 'border-color 0.2s',
                  }}
                  onFocus={e => e.target.style.borderColor = 'var(--accent-blue)'}
                  onBlur={e => e.target.style.borderColor = 'var(--border-color)'}
                />
                {ipSearch && (
                  <button onClick={() => setIpSearch('')} style={{
                    position: 'absolute', right: '0.75rem', top: '50%',
                    transform: 'translateY(-50%)', background: 'none',
                    border: 'none', cursor: 'pointer', color: 'var(--text-muted)',
                    display: 'flex', alignItems: 'center', padding: 0
                  }}>
                    <X size={14} />
                  </button>
                )}
              </div>

              <div className="table-wrapper">
                {filteredAlerts.length > 0 ? (
                  <table className="alert-table">
                    <thead>
                      <tr>
                        <th>Source IP</th>
                        <th>Destination IP</th>
                        <th>Protocol</th>
                        <th>Threat Type</th>
                        <th>Flows</th>
                        <th>Confidence</th>
                        <th>Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAlerts.map((alert, i) => {
                        const sevClass = alert.severity.toLowerCase();
                        const rowClass = `alert-row-${sevClass}`;
                        return (
                          <tr key={i} className={rowClass}>
                            <td style={{ fontWeight: 600 }}>{alert.src_ip}</td>
                            <td><DestinationIPCell dstIp={alert.dst_ip} /></td>
                            <td><span style={{ fontSize: '0.75rem', padding: '0.15rem 0.4rem', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', textTransform: 'uppercase' }}>{alert.protocol}</span></td>
                            <td>{alert.threat_type}</td>
                            <td style={{ color: 'var(--text-secondary)' }}>{alert.flow_count}</td>
                            <td>
                              <span className="confidence-badge">
                                {Math.round(alert.confidence * 100)}%
                              </span>
                            </td>
                            <td>
                              <span className={`severity-badge ${sevClass}`}>
                                {alert.severity}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-state">
                    <CheckCircle2 size={48} style={{ color: 'var(--severity-low)', opacity: 0.8 }} />
                    <p style={{ fontWeight: 600 }}>No threats match active filter criteria</p>
                    <p style={{ fontSize: '0.85rem' }}>Try clearing severity or protocol filters in the sidebar.</p>
                  </div>
                )}
              </div>
            </section>
          </>
        ) : (
          /* Empty state - Upload prompt */
          <div className="chart-card" style={{ flexGrow: 1, minHeight: '400px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div className="empty-state">
              <FileText size={64} className="empty-state-icon" />
              <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>No NetFlow Data Ingested</h2>
              <p style={{ maxWidth: '460px', fontSize: '0.875rem' }}>
                Please drag and drop a valid CSV file of NetFlow records to run the rule heuristics and Isolation Forest threat engines.
              </p>
              
              <button 
                onClick={async () => {
                  setLoading(true);
                  setUploadProgress("Simulating file creation...");
                  try {
                    // Trigger backend generation or fetch if we had preset data
                    setError(null);
                    // Just prompt manual upload
                    document.getElementById('netflow-file-input').click();
                  } finally {
                    setLoading(false);
                  }
                }}
                className="filter-select"
                style={{ 
                  width: 'auto', 
                  backgroundColor: 'var(--accent-purple)', 
                  border: 'none',
                  fontWeight: 600, 
                  padding: '0.75rem 1.5rem', 
                  marginTop: '1rem',
                  boxShadow: '0 4px 14px rgba(139, 92, 246, 0.4)'
                }}
              >
                Choose File to Upload
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;