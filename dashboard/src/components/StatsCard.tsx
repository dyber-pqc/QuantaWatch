interface StatsCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  trend?: {
    value: string;
    positive: boolean;
  };
  accentColor?: "blue" | "purple" | "green" | "red" | "yellow";
}

const accentStyles = {
  blue: {
    iconBg: "bg-primary-500/15",
    iconText: "text-primary-400",
    valueBorder: "border-primary-500/20",
  },
  purple: {
    iconBg: "bg-accent-500/15",
    iconText: "text-accent-400",
    valueBorder: "border-accent-500/20",
  },
  green: {
    iconBg: "bg-green-500/15",
    iconText: "text-green-400",
    valueBorder: "border-green-500/20",
  },
  red: {
    iconBg: "bg-red-500/15",
    iconText: "text-red-400",
    valueBorder: "border-red-500/20",
  },
  yellow: {
    iconBg: "bg-yellow-500/15",
    iconText: "text-yellow-400",
    valueBorder: "border-yellow-500/20",
  },
};

export default function StatsCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  accentColor = "blue",
}: StatsCardProps) {
  const accent = accentStyles[accentColor];

  return (
    <div
      className={`rounded-xl bg-surface-900 border ${accent.valueBorder} p-5 transition-all duration-200 hover:border-opacity-50`}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <p className="text-sm font-medium text-gray-400">{title}</p>
          <p className="text-3xl font-bold text-white tracking-tight">
            {typeof value === "number" ? value.toLocaleString() : value}
          </p>
          {subtitle && (
            <p className="text-xs text-gray-500">{subtitle}</p>
          )}
          {trend && (
            <p
              className={`text-xs font-medium ${
                trend.positive ? "text-green-400" : "text-red-400"
              }`}
            >
              {trend.positive ? "+" : ""}
              {trend.value}
            </p>
          )}
        </div>
        <div className={`p-2.5 rounded-lg ${accent.iconBg} ${accent.iconText}`}>
          {icon}
        </div>
      </div>
    </div>
  );
}
