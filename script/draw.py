import matplotlib.pyplot as plt
import numpy as np

# names = ['DelegateCall', 'ArbiStorageWrite', 'All', 'ArbitraryJump', 'DepEvil', "Servers", "ArbitraryJumpWithFuncSeqOrder", "SelfDestruct"]
# warden = [0.26, 2.30, 8.69, 0.12, 3.12, 0.37, 0.37] 
# mythril = [10.75, 12.13, 191.93, 4.50, 90.14, 19.45, 0]

# name, warden, mythril
datas = [
    ('DelegateCall', 0.26, 10.75),
    ('ArbiStorageWrite', 2.3, 12.13),
    ('All', 8.69, 191.93),
    ('ArbitraryJump', 0.12, 4.5),
    ('DepEvil', 3.12, 0),
    ('Servers', 0.37, 19.45),
    ('ArbitraryJumpWithFuncSeqOrder', 0.37, 0),
]

names   = [data[0] for data in datas]
warden  = [data[1] for data in datas]
mythril = [data[2] for data in datas]

# 设置图表大小
plt.figure(figsize=(18, 9))

# 设置每个任务的位置
x = np.arange(len(names))

# 设置每个小 bar 的宽度
bar_width = 0.35

# 创建图表和子图
fig, ax = plt.subplots()

# 绘制工具 A 的小 bar
rects1 = ax.bar(x - bar_width/2, warden, bar_width, label='warden')

# 绘制工具 B 的小 bar
rects2 = ax.bar(x + bar_width/2, mythril, bar_width, label='mythril')

# 添加标题和标签
ax.set_title('Contract Vuln Found Time Comparison')
ax.set_xlabel('Contracts')
ax.set_ylabel('Time (seconds)')

# 添加 x 轴刻度
# 添加 x 轴刻度，并设置旋转角度为 45 度
ax.set_xticks(x)
ax.set_xticklabels(names, rotation=45, ha='right')

# 添加图例
ax.legend()

# 自动调整布局
fig.tight_layout()

# 展示图表
plt.show()