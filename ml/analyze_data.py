import pandas as pd
import numpy as np

# Load data
normal = pd.read_csv('../data/normal_traffic.csv')
attack = pd.read_csv('../data/attack_traffic.csv')

print('='*60)
print('DATA DISTRIBUTION ANALYSIS - HONEST CHECK')
print('='*60)

# Compare key features
features = ['packet_rate', 'unique_ports', 'connection_count', 'duration']
for feat in features:
    print(f'\n{feat.upper()}:')
    print(f'  Normal:  min={normal[feat].min():.1f}  mean={normal[feat].mean():.1f}  max={normal[feat].max():.1f}')
    print(f'  Attack:  min={attack[feat].min():.1f}  mean={attack[feat].mean():.1f}  max={attack[feat].max():.1f}')
    
    # Check overlap
    normal_range = (normal[feat].min(), normal[feat].max())
    attack_range = (attack[feat].min(), attack[feat].max())
    overlap = max(0, min(normal_range[1], attack_range[1]) - max(normal_range[0], attack_range[0]))
    total_range = max(normal_range[1], attack_range[1]) - min(normal_range[0], attack_range[0])
    overlap_pct = (overlap / total_range * 100) if total_range > 0 else 0
    print(f'  Overlap: {overlap_pct:.1f}% of total range')

# Check how many attacks fall within normal ranges
print('\n' + '='*60)
print('ATTACKS WITHIN NORMAL RANGES (CRITICAL CHECK):')
print('='*60)
for feat in features:
    n_min, n_max = normal[feat].min(), normal[feat].max()
    within_normal = ((attack[feat] >= n_min) & (attack[feat] <= n_max)).sum()
    pct = within_normal / len(attack) * 100
    print(f'{feat}: {within_normal}/{len(attack)} ({pct:.1f}%) attacks within normal range')

# Check per-attack type
print('\n' + '='*60)
print('PER-ATTACK TYPE RANGES:')
print('='*60)
for atype in sorted(attack['attack_type'].unique()):
    subset = attack[attack['attack_type'] == atype]
    pr_min, pr_max = subset['packet_rate'].min(), subset['packet_rate'].max()
    cc_min, cc_max = subset['connection_count'].min(), subset['connection_count'].max()
    print(f'\n{atype}:')
    print(f'  packet_rate: {pr_min:.1f} - {pr_max:.1f}')
    print(f'  connection_count: {cc_min:.0f} - {cc_max:.0f}')
    
    # Check if it overlaps with normal
    normal_pr = (normal['packet_rate'].min(), normal['packet_rate'].max())
    if pr_min <= normal_pr[1] and pr_max >= normal_pr[0]:
        print(f'  WARNING: packet_rate overlaps with normal!')
    
print('\n' + '='*60)
print('COMBINATION ANALYSIS (Why high accuracy?):')
print('='*60)
print('\nChecking if features ALONE can distinguish attacks...')
# For attacks that have packet_rate in normal range
pr_normal_range = attack[(attack['packet_rate'] >= normal['packet_rate'].min()) & 
                          (attack['packet_rate'] <= normal['packet_rate'].max())]
print(f'\nAttacks with packet_rate in normal range: {len(pr_normal_range)}/{len(attack)} ({len(pr_normal_range)/len(attack)*100:.1f}%)')

if len(pr_normal_range) > 0:
    print('\nBut their OTHER features:')
    print(f'  connection_count: mean={pr_normal_range["connection_count"].mean():.1f} (normal max={normal["connection_count"].max():.0f})')
    print(f'  duration: mean={pr_normal_range["duration"].mean():.1f} (normal mean={normal["duration"].mean():.1f})')
    print(f'  unique_ports: mean={pr_normal_range["unique_ports"].mean():.1f} (normal mean={normal["unique_ports"].mean():.1f})')

print('\n' + '='*60)
print('VERDICT:')
print('='*60)
# Calculate how many attacks are distinguishable by SIMPLE rules
easy_attacks = 0
reasons = []

# High packet rate (> 95th percentile of normal)
pr_threshold = normal['packet_rate'].quantile(0.95)
high_pr = (attack['packet_rate'] > pr_threshold).sum()
easy_attacks = max(easy_attacks, high_pr)
reasons.append(f'{high_pr} attacks have packet_rate > 95th percentile normal ({pr_threshold:.1f})')

# High connection count (> max normal)
cc_threshold = normal['connection_count'].max()
high_cc = (attack['connection_count'] > cc_threshold).sum()
easy_attacks = max(easy_attacks, high_cc)
reasons.append(f'{high_cc} attacks have connection_count > normal max ({cc_threshold})')

# Protocol anomaly
weird_proto = attack[~attack['protocol'].isin(['TCP', 'UDP', 'ICMP'])].shape[0]
reasons.append(f'{weird_proto} attacks use unusual protocols (GRE, ESP, etc.)')

print(f'\nAttacks distinguishable by simple rules: {easy_attacks}/{len(attack)} ({easy_attacks/len(attack)*100:.1f}%)')
print('\nReasons:')
for r in reasons:
    print(f'  - {r}')

print(f'\nConclusion: The problem is {"TOO EASY" if easy_attacks/len(attack) > 0.8 else "REASONABLY HARD"}')
print(f'High accuracy ({0.9851:.4f} F1) is {"SUSPICIOUS - data too clean" if easy_attacks/len(attack) > 0.9 else "PLAUSIBLE"}')
