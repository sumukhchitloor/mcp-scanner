import React from 'react';
import { LucideIcon } from 'lucide-react';
import { cn } from '@/utils/cn';

interface SecurityMetricsCardProps {
  title: string;
  value: string | number | React.ReactNode;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  color: 'blue' | 'red' | 'green' | 'purple' | 'orange';
}


export default function SecurityMetricsCard({
  title,
  value,
  icon: Icon,
  trend
}: Omit<SecurityMetricsCardProps, 'color'>) {
  return (
    <div className="p-0">
      {/* Icon */}
      <div className="flex items-center justify-center w-12 h-12 mb-4 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
        <Icon className="w-6 h-6 text-cyan-400" />
      </div>

      {/* Content */}
      <div className="space-y-2">
        <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider font-mono">
          {title}
        </h3>
        
        <div className="flex items-end justify-between">
          <div className="text-3xl font-bold text-white font-mono">
            {value}
          </div>
          
          {trend && (
            <div className={cn(
              'flex items-center text-sm font-medium font-mono',
              trend.isPositive ? 'text-emerald-400' : 'text-red-400'
            )}>
              <span>{trend.isPositive ? '+' : '-'}{trend.value}%</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
