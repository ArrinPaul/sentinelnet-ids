import pandas as pd
import numpy as np

print('='*80)
print('DATASET COMPARISON: SIMPLE vs REALISTIC')
print('='*80)

for mode in ['simple', 'realistic']:
    normal = pd.read_csv(f'../data/{mode}/normal_traffic.csv')
    attack = pd.read_csv(f'../data/{mode}/attack_traffic.csv')
    
    print(f'\n{"="*80}')
    print(f'{mode.upper()} MODE')
    print(f'{"="*80}')
    
    # Compare key features
    features = ['packet_rate', 'unique_ports', 'connection_count', 'duration']
    for feat in features:
        print(f'\n{feat}:')
        print(f'  Normal:  min={normal[feat].min():.0f}  mean={normal[feat].mean():.1f}  max={normal[feat].max():.0f}')
        print(f'  Attack:  min={attack[feat].min():.0f}  mean={attack[feat].mean():.1f}  max={attack[feat].max():.0f}')
        
        # Check overlap
        normal_range = (normal[feat].min(), normal[feat].max())
        attack_range = (attack[feat].min(), attack[feat].max())
        overlap = max(0, min(normal_range[1], attack_range[1]) - max(normal_range[0], attack_range[0]))
        total_range = max(normal_range[1], attack_range[1]) - min(normal_range[0], attack_range[0])
        overlap_pct = (overlap / total_range * 100) if total_range > 0 else 0
        print(f'  Range overlap: {overlap_pct:.1f}%')
    
    # Check how many attacks fall within normal ranges
    print(f'\n{"─"*80}')
    print('ATTACKS WITHIN NORMAL RANGES:')
    print(f'{"─"*80}')
    for feat in features:
        n_min, n_max = normal[feat].min(), normal[feat].max()
        within_normal = ((attack[feat] >= n_min) & (attack[feat] <= n_max)).sum()
        pct = within_normal / len(attack) * 100
        print(f'  {feat:<20} {within_normal:>4}/{len(attack)} ({pct:>5.1f}%) attacks within normal range')
    
    # Calculate distinguishability
    print(f'\n{"─"*80}')
    print('EASY DETECTION (Simple Rules):')
    print(f'{"─"*80}')
    
    # High connection count (> 95th percentile of normal)
    cc_threshold = normal['connection_count'].quantile(0.95)
    high_cc = (attack['connection_count'] > cc_threshold).sum()
    print(f'  connection_count > 95th percentile ({cc_threshold:.0f}): {high_cc}/{len(attack)} ({high_cc/len(attack)*100:.1f}%)')
    
    # High packet rate (> 95th percentile of normal)
    pr_threshold = normal['packet_rate'].quantile(0.95)
    high_pr = (attack['packet_rate'] > pr_threshold).sum()
    print(f'  packet_rate > 95th percentile ({pr_threshold:.0f}): {high_pr}/{len(attack)} ({high_pr/len(attack)*100:.1f}%)')
    
    # Unusual protocols
    weird_proto = attack[~attack['protocol'].isin(['TCP', 'UDP', 'ICMP'])].shape[0]
    print(f'  Unusual protocols (GRE, ESP, etc.): {weird_proto}/{len(attack)} ({weird_proto/len(attack)*100:.1f}%)')
    
    # Total easily detectable
    detectable = max(high_cc, high_pr)
    print(f'\n  Total easily detectable (simple rules): {detectable}/{len(attack)} ({detectable/len(attack)*100:.1f}%)')
    
    if detectable / len(attack) > 0.85:
        print(f'  ⚠️  TOO EASY - Problem is trivial')
    elif detectable / len(attack) > 0.70:
        print(f'  ⚙️  MODERATE - Reasonable but still easy')
    else:
        print(f'  ✓  REALISTIC - Model will need to learn patterns')

print('\n' + '='*80)
print('SUMMARY:')
print('='*80)
print('Simple mode:    Clear separation, high accuracy expected (~98% F1)')
print('                Good for: Proof of concept, learning pipeline')
print('')
print('Realistic mode: More overlap, lower accuracy expected (~85-92% F1)')
print('                Good for: Real-world evaluation, production testing')
print('='*80)
