# evil.py
def get_taint():
    user_input = input("Source: ")
    # 局部变量 user_input 被污染
    return user_input # 返回污点

def dangerous_sink(data, options):
    # 参数 'data' 被用作 Sink
    eval(data)
    print(options) # 'options' 不是 Sink

def safe_func(a, b):
    # 没有 Sink，没有 Source，没有返回污点
    return a + b

# --- 主程序流 ---
# 1. Taint-Out 传播 (x = get_taint() 应该将 x 标记为污点)
x = get_taint()

# 2. Taint-In 报告 (待在 Scanner.visit_Call 中实现)
dangerous_sink(x, 10)