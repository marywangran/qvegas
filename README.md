# qvegas
TCP Qvegas is very well!
类似微软的Compound TCP，qvegas结合了reno和标准vegas。key ponit如下：
1.用reno提高vegas的抢占性
2.将reno分量和vegas分量完全分离，独立增窗减窗
所以说，这也是一种混合的TCP拥塞控制算法
