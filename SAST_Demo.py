import ast


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
        self.TAINTED_SOURCES={'input'}
        self.TAINT_SINKS = {'exec', 'eval', 'system'}
        self.func_sum={}


    def visit_FunctionDef(self, node):
        func_name=node.name

        args_list=[arg.arg for arg in node.args.args]

        analyzer = SubScanner(func_name,self.TAINTED_SOURCES,args_list)

        for item in node.body:
            analyzer.visit(item)
        analyzer.summary['args']=args_list
        self.func_sum[func_name]=analyzer.summary
        print(func_name,self.func_sum[func_name])

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

        # 检查是否是 Sink (使用硬编码或传递的 Sink 列表)
        if func_name in self.TAINT_SINKS:
            for arg_node in node.args:
                if isinstance(arg_node, ast.Name) and arg_node.id in self.tainted_vars:
                    print(f"**[GLOBAL VULNERABILITY FOUND]**")
                    print(f"  Sink found at line {node.lineno}")
                    print(f"  Tainted variable: {arg_node.id}")
                    # 你可以决定是否将这个信息记录到 summary 中
        elif func_name in self.func_sum:
            summary=self.func_sum[func_name]

            full_params = summary.get('args',[])
            sink_params = summary.get('sinks',[])

            for i,arg_node in enumerate(node.args):
                if i <len(full_params):
                    param=full_params[i]
                    if param in sink_params:
                        if isinstance(arg_node, ast.Name) and arg_node.id in self.tainted_vars:
                            print(f"**[IPA VULNERABILITY FOUND]**")
                            print(f"  Sink function: {func_name} called at line {node.lineno}")
                            print(f"  Tainted variable: {arg_node.id}")
                            print(f"  Flow: {arg_node.id} (Tainted) -> Parameter '{param}' (Sink)")

                            break




        self.generic_visit(node)


    def visit_Assign(self, node):
        #读取左侧变量名，默认为未污染
        if isinstance(node.targets[0], ast.Name):
            target_name = node.targets[0].id
            is_tainted = False

            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id

                if func_name in self.TAINTED_SOURCES:
                    is_tainted = True
                elif func_name in self.func_sum:
                    summary = self.func_sum[func_name]
                    if summary.get("return tainted"):
                        print(f"[IPA] Taint propagated from Taint-Out function: {func_name} -> {target_name}")
                        is_tainted = True


            elif isinstance(node.value,ast.BinOp):
                left_istainted=isinstance(node.value.left,ast.Name) and node.value.left.id in self.tainted_vars
                right_istainted=isinstance(node.value.right,ast.Name) and node.value.right.id in self.tainted_vars
                if left_istainted or right_istainted:
                    is_tainted=True

            elif isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                is_tainted=True

            if is_tainted:
                self.tainted_vars.add(target_name)
            self.generic_visit(node)


class SubScanner(ast.NodeVisitor):
    def __init__(self,func_name,TAINTED_SOURCES,args_list):
        self.func_name=func_name
        self.tainted_vars=set()
        self.SOURCES= TAINTED_SOURCES
        self.summary={"return tainted":False,"sinks":[]}
        self.args_list=args_list
        print(f"analyzing {func_name}"+"-"*20)

    def visit_Assign(self, node):
        # 简化处理：只处理单变量赋值
        if not isinstance(node.targets[0], ast.Name):
            self.generic_visit(node)
            return

        target_name = node.targets[0].id
        is_tainted = False
        value_node = node.value

        # 1. Taint Injection (Source: target = input())
        if isinstance(value_node, ast.Call) and isinstance(value_node.func, ast.Name):
            if value_node.func.id in self.SOURCES:
                is_tainted = True

        # 2. Taint Propagation (BinOp: target = a + b)
        elif isinstance(value_node, ast.BinOp):
            # 检查左右操作数是否是 '被污染的变量'
            left_is_tainted = isinstance(value_node.left, ast.Name) and value_node.left.id in self.tainted_vars
            right_is_tainted = isinstance(value_node.right, ast.Name) and value_node.right.id in self.tainted_vars

            if left_is_tainted or right_is_tainted:
                is_tainted = True

        # 3. Taint Propagation (Name: target = source_var)
        elif isinstance(value_node, ast.Name) and value_node.id in self.tainted_vars:
            is_tainted = True

        if is_tainted:
            self.tainted_vars.add(target_name)

        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = ""
        #需要在 SubScanner 中传递或定义 Sinks
        TAINT_SINKS = {'exec', 'eval', 'system'}

        if isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in TAINT_SINKS:
            for arg_node in node.args:
                if isinstance(arg_node, ast.Name):
                    var_name = arg_node.id

                    if var_name in self.tainted_vars:
                    #使用 SubScanner 的上下文来报告漏洞
                        print(f"**[INTRA-PROCEDURAL VULNERABILITY FOUND]**")
                        print(f"  Sink found in {self.func_name} at line {node.lineno}")
                        print(f"  Tainted variable: {arg_node.id}")
                        pass

                    if var_name in self.args_list:
                        # 发现一个参数被用作 Sink，将其记录到摘要中
                        if var_name not in self.summary['sinks']:
                            self.summary['sinks'].append(var_name)
                            print(f"[IPA Taint-In] Parameter '{var_name}' is a potential Sink.")



        self.generic_visit(node)

    def visit_Return(self, node):
        if node.value is not None and isinstance(node.value,ast.Name):
            return_var_name=node.value.id
            if return_var_name in self.tainted_vars:
                self.summary["return tainted"] = True

        self.generic_visit(node)





with open("./evil.py","r",encoding="utf-8") as f:
    c=f.read()
    f.close()

print("--------------------------------------")
tree=ast.parse(c)
scanner=Scanner()
print("--------------------------------------")
scanner.visit(tree)








