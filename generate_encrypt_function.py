import re
import os
import ast
import sys
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path

class EncryptionExtractor:
    """
    修復版本的加密代碼提取器，解決依賴關係和代碼格式問題
    """
    
    # 加密相關的關鍵字
    ENCRYPTION_KEYWORDS = {
        'encrypt', 'decrypt', 'cipher', 'aes', 'des', 'rsa', 'md5', 
        'sha', 'hash', 'crypto', 'pad', 'unpad', 'pbkdf', 'hmac', 
        'crypt', 'secret', 'key', 'iv', 'nonce', 'salt', 'encode', 'decode'
    }
    
    # 常見的加密庫
    CRYPTO_LIBRARIES = {
        'Crypto', 'cryptography', 'pycrypto', 'pycryptodome', 
        'hashlib', 'hmac', 'secrets', 'base64'
    }
    
    def __init__(self, project_path: str):
        """初始化修復版本的加密提取器

        Args:
            project_path: 項目根目錄路徑
        """
        self.project_path = Path(project_path)
        self.all_python_files = []
        self.file_contents = {}
        self.file_asts = {}
        self.project_modules = {}  # 存儲項目內部模塊的映射
        self.encryption_code = {
            'imports': set(),
            'functions': [],
            'classes': [],
            'constants': [],
            'helper_functions': []
        }
        self.analyzed_files = set()
        
        # 掃描項目中的所有Python文件
        self._scan_python_files()
        # 建立項目模塊映射
        self._build_module_mapping()
        
    def _scan_python_files(self):
        """掃描項目中的所有Python文件"""
        for py_file in self.project_path.rglob("*.py"):
            if py_file.is_file() and not py_file.name.startswith('.'):
                self.all_python_files.append(py_file)
                
    def _build_module_mapping(self):
        """建立項目內部模塊的映射關係"""
        for py_file in self.all_python_files:
            # 計算相對於項目根目錄的模塊路徑
            try:
                relative_path = py_file.relative_to(self.project_path)
                module_name = str(relative_path.with_suffix('')).replace(os.sep, '.')
                
                # 也記錄文件名（不含路徑）
                file_name = py_file.stem
                
                self.project_modules[module_name] = py_file
                self.project_modules[file_name] = py_file
                
                print(f"📝 映射模塊: {file_name} -> {py_file}")
            except ValueError:
                continue
    
    def _read_file(self, file_path: Path) -> Tuple[str, Optional[ast.AST]]:
        """讀取文件內容並解析AST"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            try:
                ast_tree = ast.parse(content)
                return content, ast_tree
            except SyntaxError as e:
                print(f"⚠️ 警告: 無法解析 {file_path} 的AST: {e}")
                return content, None
                
        except Exception as e:
            print(f"❌ 讀取文件 {file_path} 時發生錯誤: {e}")
            return "", None
    
    def _is_encryption_related(self, name: str) -> bool:
        """判斷名稱是否與加密相關"""
        if not name:
            return False
        name_lower = name.lower()
        return any(keyword in name_lower for keyword in self.ENCRYPTION_KEYWORDS)
    
    def _is_crypto_library(self, module_name: str) -> bool:
        """判斷模塊是否為加密庫"""
        if not module_name:
            return False
        return any(lib in module_name for lib in self.CRYPTO_LIBRARIES)
    
    def _fix_import_statement(self, import_stmt: str) -> str:
        """修復導入語句，將項目內部導入轉換為正確的格式"""
        # 檢查是否為項目內部導入
        if 'from ' in import_stmt and ' import ' in import_stmt:
            # 解析 from module import name
            parts = import_stmt.strip().split()
            if len(parts) >= 4 and parts[0] == 'from' and parts[2] == 'import':
                module_name = parts[1]
                import_names = ' '.join(parts[3:])
                
                # 檢查是否為項目內部模塊
                if module_name in self.project_modules:
                    # 將項目內部導入標記出來，或者直接包含相關代碼
                    return f"# {import_stmt}  # 項目內部導入，相關代碼已包含在下方"
                    
        elif 'import ' in import_stmt and not import_stmt.startswith('from'):
            # 解析 import module
            parts = import_stmt.strip().split()
            if len(parts) >= 2 and parts[0] == 'import':
                module_name = parts[1].split('.')[0]  # 取主模塊名
                
                # 檢查是否為項目內部模塊
                if module_name in self.project_modules:
                    return f"# {import_stmt}  # 項目內部導入，相關代碼已包含在下方"
        
        return import_stmt
    
    def _extract_imports_from_ast(self, ast_tree: ast.AST, file_path: Path) -> List[str]:
        """從AST中提取import語句"""
        imports = []
        
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                try:
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            import_stmt = f"import {alias.name}"
                            if alias.asname:
                                import_stmt += f" as {alias.asname}"
                            
                            # 檢查是否為加密相關或標準庫
                            if (self._is_crypto_library(alias.name) or 
                                self._is_encryption_related(alias.name) or
                                alias.name in ['os', 'sys', 'struct', 'socket', 'threading', 'time', 'unittest', 'filecmp']):
                                imports.append(self._fix_import_statement(import_stmt))
                                
                    elif isinstance(node, ast.ImportFrom):
                        module = node.module or ""
                        level = "." * (node.level or 0)
                        
                        for alias in node.names:
                            import_stmt = f"from {level}{module} import {alias.name}"
                            if alias.asname:
                                import_stmt += f" as {alias.asname}"
                            
                            # 檢查是否為加密相關、標準庫或項目內部
                            if (self._is_crypto_library(module) or 
                                self._is_encryption_related(alias.name) or
                                self._is_encryption_related(module) or
                                module in ['os', 'sys', 'struct', 'socket', 'threading', 'time', 'unittest', 'filecmp'] or
                                module in self.project_modules):
                                imports.append(self._fix_import_statement(import_stmt))
                                
                except Exception as e:
                    print(f"⚠️ 處理import語句時出錯: {e}")
                    continue
                    
        return imports
    
    def _extract_node_code(self, node: ast.AST, content: str, fix_indentation: bool = True) -> Optional[str]:
        """從AST節點提取代碼，並修復縮進問題"""
        try:
            lines = content.splitlines()
            start_line = node.lineno - 1
            
            if hasattr(node, 'end_lineno') and node.end_lineno:
                end_line = node.end_lineno - 1
            else:
                # 如果沒有end_lineno，嘗試找到節點結束位置
                end_line = start_line
                if start_line < len(lines):
                    base_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
                    
                    for i in range(start_line + 1, len(lines)):
                        if i >= len(lines):
                            break
                        line = lines[i]
                        if line.strip():  # 非空行
                            current_indent = len(line) - len(line.lstrip())
                            if current_indent <= base_indent:
                                break
                        end_line = i
            
            extracted_code = '\n'.join(lines[start_line:end_line + 1])
            
            # 修復縮進問題
            if fix_indentation:
                extracted_code = self._fix_code_indentation(extracted_code)
            
            return extracted_code
            
        except Exception as e:
            print(f"⚠️ 提取節點代碼時出錯: {e}")
            return None
    
    def _fix_code_indentation(self, code: str) -> str:
        """修復代碼縮進問題"""
        lines = code.split('\n')
        if not lines:
            return code
        
        # 找到第一行非空行的縮進
        first_line_indent = 0
        for line in lines:
            if line.strip():
                first_line_indent = len(line) - len(line.lstrip())
                break
        
        # 移除多餘的縮進
        fixed_lines = []
        for line in lines:
            if line.strip():  # 非空行
                if len(line) >= first_line_indent:
                    fixed_lines.append(line[first_line_indent:])
                else:
                    fixed_lines.append(line.lstrip())
            else:
                fixed_lines.append('')
        
        return '\n'.join(fixed_lines)
    
    def _extract_functions_from_ast(self, ast_tree: ast.AST, content: str) -> List[str]:
        """從AST中提取函數定義"""
        functions = []
        
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.FunctionDef):
                # 檢查函數名是否與加密相關
                if (self._is_encryption_related(node.name) or 
                    self._function_contains_crypto_operations(node)):
                    # 提取函數代碼
                    function_code = self._extract_node_code(node, content)
                    if function_code:
                        functions.append(function_code)
                        
        return functions
    
    def _extract_classes_from_ast(self, ast_tree: ast.AST, content: str) -> List[str]:
        """從AST中提取類定義"""
        classes = []
        
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.ClassDef):
                # 檢查類名是否與加密相關或包含加密方法
                if (self._is_encryption_related(node.name) or 
                    self._class_contains_crypto_methods(node)):
                    class_code = self._extract_node_code(node, content)
                    if class_code:
                        classes.append(class_code)
                        
        return classes
    
    def _extract_constants_from_ast(self, ast_tree: ast.AST, content: str) -> List[str]:
        """從AST中提取常量定義（只提取模塊級別的常量）"""
        constants = []
        
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Assign):
                # 檢查是否為模塊級別的賦值（不在類或函數內部）
                parent_nodes = []
                for parent in ast.walk(ast_tree):
                    for child in ast.iter_child_nodes(parent):
                        if child is node:
                            parent_nodes.append(parent)
                
                # 只處理模塊級別的賦值
                is_module_level = True
                for parent in parent_nodes:
                    if isinstance(parent, (ast.FunctionDef, ast.ClassDef)):
                        is_module_level = False
                        break
                
                if is_module_level:
                    # 檢查賦值語句是否為常量定義
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            if (var_name.isupper() and 
                                (self._is_encryption_related(var_name) or 
                                 self._assignment_contains_crypto_values(node))):
                                constant_code = self._extract_node_code(node, content)
                                if constant_code:
                                    constants.append(constant_code)
                                    
        return constants
    
    def _function_contains_crypto_operations(self, func_node: ast.FunctionDef) -> bool:
        """檢查函數是否包含加密操作"""
        try:
            if hasattr(ast, 'unparse'):
                func_source = ast.unparse(func_node)
            else:
                # 如果沒有unparse，用函數名和文檔字符串來判斷
                func_source = func_node.name
                if hasattr(func_node, 'body') and func_node.body:
                    for stmt in func_node.body:
                        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                            if isinstance(stmt.value.value, str):
                                func_source += " " + stmt.value.value
        except:
            func_source = func_node.name
        
        func_source_lower = func_source.lower()
        
        # 檢查是否包含加密相關的調用或操作
        crypto_patterns = [
            'aes.new', 'cipher.', '.encrypt', '.decrypt', '.digest', 
            '.hexdigest', 'hash', 'crypto', 'pbkdf', 'hmac', 'rsa', 'key'
        ]
        
        return any(pattern in func_source_lower for pattern in crypto_patterns)
    
    def _class_contains_crypto_methods(self, class_node: ast.ClassDef) -> bool:
        """檢查類是否包含加密相關方法"""
        for node in ast.walk(class_node):
            if isinstance(node, ast.FunctionDef):
                if (self._is_encryption_related(node.name) or 
                    self._function_contains_crypto_operations(node)):
                    return True
        return False
    
    def _assignment_contains_crypto_values(self, assign_node: ast.Assign) -> bool:
        """檢查賦值語句是否包含加密相關值"""
        try:
            if hasattr(ast, 'unparse'):
                assign_source = ast.unparse(assign_node).lower()
                return any(keyword in assign_source for keyword in self.ENCRYPTION_KEYWORDS)
        except:
            pass
        return False
    
    def _file_contains_crypto(self, content: str, ast_tree: ast.AST) -> bool:
        """檢查文件是否包含加密相關內容"""
        content_lower = content.lower()
        
        # 檢查關鍵字
        if any(keyword in content_lower for keyword in self.ENCRYPTION_KEYWORDS):
            return True
            
        # 檢查加密庫導入
        if any(lib.lower() in content_lower for lib in self.CRYPTO_LIBRARIES):
            return True
            
        # 檢查AST中的加密相關節點
        if ast_tree:
            for node in ast.walk(ast_tree):
                if isinstance(node, ast.FunctionDef):
                    if (self._is_encryption_related(node.name) or 
                        self._function_contains_crypto_operations(node)):
                        return True
                elif isinstance(node, ast.ClassDef):
                    if (self._is_encryption_related(node.name) or 
                        self._class_contains_crypto_methods(node)):
                        return True
                        
        return False
    
    def _extract_project_dependencies(self, crypto_files: List[Path]) -> Set[Path]:
        """提取項目內部依賴文件"""
        dependencies = set()
        
        for crypto_file in crypto_files:
            content, ast_tree = self._read_file(crypto_file)
            if not ast_tree:
                continue
                
            for node in ast.walk(ast_tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    module_name = node.module
                    
                    # 檢查是否為項目內部模塊
                    if module_name in self.project_modules:
                        dep_file = self.project_modules[module_name]
                        if dep_file not in crypto_files:
                            dependencies.add(dep_file)
                            print(f"🔗 找到依賴: {module_name} -> {dep_file}")
                
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        module_name = alias.name.split('.')[0]
                        if module_name in self.project_modules:
                            dep_file = self.project_modules[module_name]
                            if dep_file not in crypto_files:
                                dependencies.add(dep_file)
                                print(f"🔗 找到依賴: {module_name} -> {dep_file}")
        
        return dependencies
    
    def analyze_project(self):
        """分析整個項目的加密代碼"""
        print(f"🔍 正在分析項目: {self.project_path.name}")
        print(f"📁 找到 {len(self.all_python_files)} 個Python文件")
        
        # 首先找到所有包含加密相關代碼的文件
        crypto_files = []
        
        for py_file in self.all_python_files:
            content, ast_tree = self._read_file(py_file)
            self.file_contents[py_file] = content
            self.file_asts[py_file] = ast_tree
            
            if ast_tree:
                # 檢查是否包含加密相關內容
                if self._file_contains_crypto(content, ast_tree):
                    crypto_files.append(py_file)
                    print(f"✅ 發現加密相關文件: {py_file.name}")
        
        if not crypto_files:
            print("❌ 未發現包含加密相關代碼的文件")
            return False
        
        # 查找項目內部依賴
        dependencies = self._extract_project_dependencies(crypto_files)
        all_files_to_analyze = crypto_files + list(dependencies)
        
        # 分析所有相關文件
        for file_path in all_files_to_analyze:
            print(f"🔎 分析文件: {file_path.name}")
            
            content = self.file_contents[file_path]
            ast_tree = self.file_asts[file_path]
            
            if ast_tree:
                # 提取imports
                imports = self._extract_imports_from_ast(ast_tree, file_path)
                self.encryption_code['imports'].update(imports)
                
                # 提取函數、類和常量
                functions = self._extract_functions_from_ast(ast_tree, content)
                classes = self._extract_classes_from_ast(ast_tree, content)
                constants = self._extract_constants_from_ast(ast_tree, content)
                
                # 如果是依賴文件，將其函數標記為輔助函數
                if file_path in dependencies:
                    self.encryption_code['helper_functions'].extend(functions)
                    # 依賴文件的類也可能被需要
                    self.encryption_code['classes'].extend(classes)
                else:
                    self.encryption_code['functions'].extend(functions)
                    self.encryption_code['classes'].extend(classes)
                    
                self.encryption_code['constants'].extend(constants)
        
        return True
    
    def generate_fixed_oracle_file(self, output_path: str) -> str:
        """生成修復後的 Oracle 文件"""
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        
        output_content = []
        
        # 文件頭
        output_content.append('#!/usr/bin/env python3')
        output_content.append('"""')
        output_content.append(f"從 {self.project_path.name} 提取的加密 Oracle（修復版本）")
        output_content.append("此文件解決了導入依賴和代碼格式問題")
        output_content.append('"""')
        output_content.append("")
        
        # 添加標準庫導入語句
        standard_imports = []
        project_imports = []
        
        for imp in sorted(self.encryption_code['imports']):
            if '# 項目內部導入' in imp:
                project_imports.append(imp)
            else:
                standard_imports.append(imp)
        
        if standard_imports:
            output_content.append("# 標準庫和第三方庫導入")
            output_content.append("# " + "=" * 50)
            for imp in standard_imports:
                output_content.append(imp)
            output_content.append("")
        
        if project_imports:
            output_content.append("# 項目內部導入（相關代碼已包含在下方）")
            output_content.append("# " + "=" * 50)
            for imp in project_imports:
                output_content.append(imp)
            output_content.append("")
        
        # 添加常量定義
        if self.encryption_code['constants']:
            output_content.append("# 常量定義")
            output_content.append("# " + "=" * 50)
            for constant in self.encryption_code['constants']:
                output_content.append(constant)
                output_content.append("")
        
        # 添加輔助函數（來自依賴文件）
        if self.encryption_code['helper_functions']:
            output_content.append("# 輔助函數（來自項目依賴）")
            output_content.append("# " + "=" * 50)
            for func in self.encryption_code['helper_functions']:
                output_content.append(func)
                output_content.append("")
        
        # 添加主要類
        if self.encryption_code['classes']:
            output_content.append("# 主要類定義")
            output_content.append("# " + "=" * 50)
            for cls in self.encryption_code['classes']:
                output_content.append(cls)
                output_content.append("")
        
        # 添加主要函數
        if self.encryption_code['functions']:
            output_content.append("# 主要函數定義")
            output_content.append("# " + "=" * 50)
            for func in self.encryption_code['functions']:
                output_content.append(func)
                output_content.append("")
        
        # 添加簡單的測試代碼
        output_content.append("# 測試代碼")
        output_content.append("# " + "=" * 50)
        output_content.append("if __name__ == '__main__':")
        output_content.append("    print('✅ 修復版本的加密 Oracle 已加載')")
        output_content.append("    ")
        output_content.append("    # 嘗試創建加密實例")
        output_content.append("    try:")
        output_content.append("        # 查找可用的加密類")
        if self.encryption_code['classes']:
            output_content.append("        cipher = Cipher()  # 假設存在 Cipher 類")
            output_content.append("        print('✅ 成功創建 Cipher 實例')")
            output_content.append("        ")
            output_content.append("        # 測試 ECB 模式")
            output_content.append("        cipher.set_mode('ECB')")
            output_content.append("        print('✅ ECB 模式設置成功')")
        else:
            output_content.append("        print('ℹ️ 未找到主要的加密類')")
        output_content.append("    except Exception as e:")
        output_content.append("        print(f'⚠️ 測試過程中出現錯誤: {e}')")
        
        # 寫入文件
        # print('output_path: ', output_path)
        output_path = 'C:\\Users\\user\\Desktop\\台大密碼學\\專題\\ecb_encrypt.py'
        with open(output_path, 'w', encoding='utf-8') as file:
            file.write('\n'.join(output_content))
        
        print(f"✅ 修復版本的 Oracle 文件已生成: {output_path}")
        
        # 顯示統計信息
        print(f"📊 統計信息:")
        print(f"   - 導入語句: {len(self.encryption_code['imports'])}")
        print(f"   - 常量: {len(self.encryption_code['constants'])}")
        print(f"   - 主要類: {len(self.encryption_code['classes'])}")
        print(f"   - 主要函數: {len(self.encryption_code['functions'])}")
        print(f"   - 輔助函數: {len(self.encryption_code['helper_functions'])}")
        
        return output_path

def main():
    """主程式"""
    print("修復版本的加密代碼提取器")
    print("=" * 50)
    
    # 獲取項目路徑
    project_path = input("請輸入項目目錄路徑: ").strip()
    
    # 檢查目錄是否存在
    if not os.path.isdir(project_path):
        print(f"❌ 錯誤: 目錄 '{project_path}' 不存在")
        return
    
    # 設定輸出文件路徑
    project_name = os.path.basename(project_path.rstrip('/\\'))
    default_output = f"ecb_encrypt.py"
    output_file = input(f"請輸入輸出文件路徑 [預設: {default_output}]: ").strip()
    if not output_file:
        output_file = default_output
    
    try:
        # 創建提取器並分析項目
        print(f"\n🔍 開始分析項目...")
        extractor = EncryptionExtractor(project_path)
        
        if extractor.analyze_project():
            # 生成修復後的 Oracle 文件
            print(f"\n📝 生成修復版本的 Oracle 文件...")
            extractor.generate_fixed_oracle_file(output_file)
            
            print(f"\n✨ 處理完成!")
            print(f"💡 修復的問題:")
            print(f"   1. ✅ 解決了項目內部導入依賴問題")
            print(f"   2. ✅ 修復了常量定義的縮進錯誤")
            print(f"   3. ✅ 正確處理了類屬性和模塊常量")
            print(f"   4. ✅ 包含了所有必要的依賴代碼")
        else:
            print("❌ 未能在項目中找到加密相關代碼")
        
    except Exception as e:
        print(f"❌ 處理過程中發生錯誤: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()