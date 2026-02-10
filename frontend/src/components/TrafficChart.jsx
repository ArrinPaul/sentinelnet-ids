import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div
      className="rounded-lg px-3 py-2 text-xs"
      style={{
        background: 'var(--color-panel)',
        border: '1px solid var(--color-panel-border)',
        boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
      }}
    >
      <p className="font-mono mb-1" style={{ color: 'var(--color-text-muted)' }}>{label}</p>
      {payload.map((entry, i) => (
        <p key={i} style={{ color: entry.color }}>
          <span className="font-semibold">{entry.value}</span>
          <span style={{ color: 'var(--color-text-muted)' }}> {entry.name}</span>
        </p>
      ))}
    </div>
  );
};

export function PacketRateChart({ data }) {
  const chartData = data.map((record, i) => ({
    time: new Date(record.timestamp).toLocaleTimeString('en-US', { hour12: false }),
    'pps': record.packet_rate,
    index: i,
  }));

  return (
    <ResponsiveContainer width="100%" height={280}>
      <AreaChart data={chartData}>
        <defs>
          <linearGradient id="packetRateGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#00e5a0" stopOpacity={0.25} />
            <stop offset="95%" stopColor="#00e5a0" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-panel-border)" />
        <XAxis
          dataKey="time"
          tick={{ fill: 'var(--color-text-muted)', fontSize: 10, fontFamily: 'JetBrains Mono' }}
          axisLine={{ stroke: 'var(--color-panel-border)' }}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: 'var(--color-text-muted)', fontSize: 10, fontFamily: 'JetBrains Mono' }}
          axisLine={{ stroke: 'var(--color-panel-border)' }}
          tickLine={false}
        />
        <Tooltip content={<CustomTooltip />} />
        <Area
          type="monotone"
          dataKey="pps"
          stroke="#00e5a0"
          strokeWidth={2}
          fill="url(#packetRateGradient)"
          dot={false}
          activeDot={{ r: 4, fill: '#00e5a0', stroke: 'var(--color-panel)', strokeWidth: 2 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function ProtocolChart({ data }) {
  const protocolCounts = {};
  data.forEach((record) => {
    const proto = record.protocol || 'Unknown';
    protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;
  });

  const chartData = Object.entries(protocolCounts).map(([name, count]) => ({
    name,
    count,
  }));

  const colors = {
    TCP: '#00e5a0',
    UDP: '#38a0ff',
    ICMP: '#ffb020',
    GRE: '#ff3b5c',
    ESP: '#a855f7',
    AH: '#ec4899',
    SCTP: '#f97316',
    IGMP: '#06b6d4',
    PIM: '#84cc16',
    Unknown: '#4a5b78',
  };

  return (
    <ResponsiveContainer width="100%" height={280}>
      <BarChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-panel-border)" />
        <XAxis
          dataKey="name"
          tick={{ fill: 'var(--color-text-muted)', fontSize: 10, fontFamily: 'JetBrains Mono' }}
          axisLine={{ stroke: 'var(--color-panel-border)' }}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: 'var(--color-text-muted)', fontSize: 10, fontFamily: 'JetBrains Mono' }}
          axisLine={{ stroke: 'var(--color-panel-border)' }}
          tickLine={false}
        />
        <Tooltip content={<CustomTooltip />} />
        <Bar dataKey="count" radius={[6, 6, 0, 0]} barSize={36}>
          {chartData.map((entry, index) => (
            <Cell key={index} fill={colors[entry.name] || '#4a5b78'} fillOpacity={0.8} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
