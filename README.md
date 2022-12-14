# sm3-length-extension-attack
  my_sm3.py：对gmssl库中的sm3.py稍加修改
  
  length extension attack.py:长度扩展攻击代码
  
  func.py：来自gmssl库，包含一些可能用到的函数

  长度扩展攻击是指针对某些允许包含额外信息的加密散列函数的攻击手段。而sm3算法主要分为两部分：消息填充和迭代压缩。在迭代压缩部分，将填充后的消息按64字节进行分组。每一个分组与8个向量（初始值为IV）加密后，更新8个向量（初始值为IV），再将新的向量值用于下一次加密。
  
  对sm3进行长度扩展攻击的实验思路如下:
  
     1,随机生成消息，使用sm3算法求出消息的哈希值hash1。
     
     2,将hash1分为8段，得到新的向量值V。
     
     3,生成附加消息,并进行填充。使用V对填充后的附加消息进行哈希计算，以得到另一个哈希值hash2。（注意：附加消息填充时，最后64比特不是表示附加消息的长度，而是表示“原始消息+消息填充+附加消息”的长度）
     
     4,使用sm3算法计算“原始消息+消息填充+附加消息”的哈希值hash3,如果hash2=hash3,则说明攻击成功。
  
实验结果截图：

<img width="407" alt="image" src="https://user-images.githubusercontent.com/110089380/181920151-e99c396c-6b5e-4058-8d17-f55c995d3cd1.png">
