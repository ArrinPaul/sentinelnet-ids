import {
  LineChart,
  Line,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

export function PacketRateChart({ data }) {
  const chartData = data.map((record, i) => ({
    time: new Date(record.timestamp).toLocaleTimeString(),
    packet_rate: record.packet_rate,
    index: i,
  }));

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
        <XAxis
          dataKey="time"
          tick={{ fill: '#6b7280', fontSize: 11 }}
          axisLine={{ stroke: '#374151' }}
        />
        <YAxis
          tick={{ fill: '#6b7280', fontSize: 11 }}
          axisLine={{ stroke: '#374151' }}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: '#111827',
            border: '1px solid #374151',
            borderRadius: '8px',
            color: '#e5e7eb',
          }}
        />
        <Line
          type="monotone"
          dataKey="packet_rate"
          stroke="#10b981"
          strokeWidth={2}
          dot={false}
          activeDot={{ r: 4, fill: '#10b981' }}
        />
      </LineChart>
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
    TCP: '#10b981',
    UDP: '#3b82f6',
    ICMP: '#f59e0b',
    GRE: '#ef4444',
    ESP: '#8b5cf6',
    AH: '#ec4899',
    SCTP: '#f97316',
    Unknown: '#6b7280',
  };

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
        <XAxis
          dataKey="name"
          tick={{ fill: '#6b7280', fontSize: 11 }}
          axisLine={{ stroke: '#374151' }}
        />
        <YAxis
          tick={{ fill: '#6b7280', fontSize: 11 }}
          axisLine={{ stroke: '#374151' }}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: '#111827',
            border: '1px solid #374151',
            borderRadius: '8px',
            color: '#e5e7eb',
          }}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {chartData.map((entry, index) => (
            <Cell key={index} fill={colors[entry.name] || '#6b7280'} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
