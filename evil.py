import os

def unsafe_function():
    user_input = input("Enter something: ")
    # 这是一个 Sink (危险点)
    eval(user_input)

def safe_function():
    print("Hello world")