from gmssl import sm3, func
import random
import my_sm3
import struct

m = str(random.random())  #随机生成消息m
hash1 = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))  #计算消息的哈希值hash1
m_len = len(m)
append_m = "220725"   # 附加消息
pad_str = ""
pad = []


def padding(msg):  #消息填充函数
    mlen = len(msg)
    msg.append(0x80)
    mlen += 1
    tail = mlen % 64
    range_end = 56
    if tail > range_end:
        range_end = range_end + 64
    for i in range(tail, range_end):
        msg.append(0x00)
    bit_len = (mlen - 1) * 8
    msg.extend([int(x) for x in struct.pack('>q', bit_len)])
    for j in range(int((mlen - 1) / 64) * 64 + (mlen - 1) % 64, len(msg)):
        global pad  #定义全局变量
        pad.append(msg[j])
        global pad_str
        pad_str += str(hex(msg[j]))
    return msg

def get_new_hash(hash1, m_len, append_m):  
    vectors = []
    message = ""
    # 将hash1分组，并将每一组转换为整数，即可得到8个新的向量值，并存储在vectors列表中
    hash_length=len(hash1)
    for i in range(0, hash_length, 8):
        tmp=int(hash1[i:i + 8], 16)
        vectors.append(tmp)

    if m_len > 64:
        for i in range(0, int(m_len / 64) * 64):
            message += 'a'
    for i in range(0, m_len % 64):
        message += 'a'
    message = func.bytes_to_list(bytes(message, encoding='utf-8'))
    message = padding(message)  #消息填充
    message.extend(func.bytes_to_list(bytes(append_m, encoding='utf-8')))
    return my_sm3.sm3_hash(message, vectors)  

hash2 = get_new_hash(hash1,m_len, append_m)  #使用新的向量值计算得到hash2
print("填充后附加消息的哈希值为:",hash2)

new_msg = func.bytes_to_list(bytes(m, encoding='utf-8'))
new_msg.extend(pad)
new_msg.extend(func.bytes_to_list(bytes(append_m, encoding='utf-8')))
new_msg_str = m + pad_str + append_m  #原始消息+消息填充+附加消息
hash3 = sm3.sm3_hash(new_msg)  #计算hash3
print("原始消息+消息填充+附加消息的哈希值为：",hash3)

#验证hash2和hash3是否相等
if hash2 == hash3:
    print("length extension attack success!")
else:
    print("length extension attack fail..")
