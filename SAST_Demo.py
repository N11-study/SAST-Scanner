import ast

from requests.packages import target

banner_n11 = """
----------------------------------------------------------------
>> N11 Static Taint Engine Operational. 
>> Target: Abstract Syntax Tree (AST) Analysis Mode.
-----------------------------------------------------------------
"""
print(banner_n11)
class Scanner(ast.NodeVisitor):

    def __init__(self):
        self.tainted_vars=set()

    def visit_FunctionDef(self, node):
        print(f"{node.lineno}line,find func_define：{node.name}")
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            func_name=node.func.id

        if func_name in ['exec','eval','system']:
            is_vulnerable = False

            for arg_name in node.args:
                if isinstance(arg_name, ast.Name):
                    arg_name=arg_name.id
                    if arg_name in self.tainted_vars:
                        is_vulnerable = True
                        break
            if is_vulnerable:
                print(f"find sink:{node.lineno}:{func_name} and variable is {arg_name}")
            self.generic_visit(node)




    def visit_Assign(self, node):
        #读取左侧变量名，默认为未污染
        if isinstance(node.targets[0], ast.Name):
            target_name = node.targets[0].id
            is_tainted = False

            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                if node.value.func.id == "input":
                    is_tainted=True

            elif isinstance(node.value,ast.BinOp):
                left_istainted=isinstance(node.value.left,ast.Call) and node.value.left in self.tainted_vars
                right_istainted=isinstance(node.value.right,ast.Call) and node.value.right in self.tainted_vars
                if left_istainted or right_istainted:
                    is_tainted=True

            elif isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                is_tainted=True

            if is_tainted:
                self.tainted_vars.add(target_name)
            self.generic_visit(node)


with open("./evil.py","r",encoding="utf-8") as f:
    c=f.read()
    f.close()

print("--------------------------------------")
tree=ast.parse(c)
scanner=Scanner()
print("--------------------------------------")
scanner.visit(tree)








