"""
Tamper Scripts for XSSMap
参考 sqlmap 的 tamper scripts 功能，用于绕过 WAF 和过滤器
"""

import base64
import re
import random
from typing import Callable, Dict, List


class TamperScript:
    def __init__(self, name: str, description: str, func: Callable[[str], str]):
        self.name = name
        self.description = description
        self.func = func
    
    def apply(self, payload: str) -> str:
        return self.func(payload)


class TamperEngine:
    def __init__(self):
        self.scripts: Dict[str, TamperScript] = {}
        self._register_builtin_scripts()
    
    def register(self, name: str, description: str):
        """装饰器：注册 tamper script"""
        def decorator(func: Callable[[str], str]):
            self.scripts[name] = TamperScript(name, description, func)
            return func
        return decorator
    
    def _register_builtin_scripts(self):
        """注册内置的 tamper scripts"""
        
        @self.register("space2comment", "将空格替换为注释符 /**/")
        def space2comment(payload: str) -> str:
            return payload.replace(" ", "/**/")
        
        @self.register("space2plus", "将空格替换为加号")
        def space2plus(payload: str) -> str:
            return payload.replace(" ", "+")
        
        @self.register("space2tab", "将空格替换为制表符")
        def space2tab(payload: str) -> str:
            return payload.replace(" ", "\t")
        
        @self.register("base64encode", "Base64 编码整个 payload")
        def base64encode(payload: str) -> str:
            return base64.b64encode(payload.encode()).decode()
        
        @self.register("hexencode", "十六进制编码")
        def hexencode(payload: str) -> str:
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        
        @self.register("urlencode", "URL 编码")
        def urlencode(payload: str) -> str:
            from urllib.parse import quote
            return quote(payload)
        
        @self.register("doubleurlencode", "双重 URL 编码")
        def doubleurlencode(payload: str) -> str:
            from urllib.parse import quote
            return quote(quote(payload))
        
        @self.register("unicodeencode", "Unicode 编码")
        def unicodeencode(payload: str) -> str:
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        
        @self.register("htmlencode", "HTML 实体编码")
        def htmlencode(payload: str) -> str:
            return ''.join(f'&#x{ord(c):x};' for c in payload)
        
        @self.register("htmlencode_dec", "HTML 实体编码（十进制）")
        def htmlencode_dec(payload: str) -> str:
            return ''.join(f'&#{ord(c)};' for c in payload)
        
        @self.register("case_switch", "随机大小写混合")
        def case_switch(payload: str) -> str:
            result = []
            for char in payload:
                if char.isalpha():
                    result.append(char.upper() if random.random() > 0.5 else char.lower())
                else:
                    result.append(char)
            return ''.join(result)
        
        @self.register("lowercase", "全部小写")
        def lowercase(payload: str) -> str:
            return payload.lower()
        
        @self.register("uppercase", "全部大写")
        def uppercase(payload: str) -> str:
            return payload.upper()
        
        @self.register("nullbyte", "在 payload 末尾添加空字节")
        def nullbyte(payload: str) -> str:
            return payload + "%00"
        
        @self.register("comment_between_tags", "在标签之间添加注释")
        def comment_between_tags(payload: str) -> str:
            payload = re.sub(r'(<\w+)', r'\1/**/', payload)
            return payload
        
        @self.register("equal2like", "将等号替换为 LIKE")
        def equal2like(payload: str) -> str:
            return payload.replace("=", " LIKE ")
        
        @self.register("randomcase", "随机大小写（仅针对标签名）")
        def randomcase(payload: str) -> str:
            def replacer(match):
                tag = match.group(0)
                return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in tag)
            return re.sub(r'<[^>]+>', replacer, payload)
        
        @self.register("charencode", "字符编码（仅编码关键字符）")
        def charencode(payload: str) -> str:
            replacements = {
                '<': '&#x3c;',
                '>': '&#x3e;',
                '"': '&#x22;',
                "'": '&#x27;',
                '/': '&#x2f;',
            }
            for char, encoded in replacements.items():
                payload = payload.replace(char, encoded)
            return payload
        
        @self.register("escape_quotes", "转义引号")
        def escape_quotes(payload: str) -> str:
            return payload.replace("'", "\\'").replace('"', '\\"')
        
        @self.register("reverse", "反转 payload")
        def reverse(payload: str) -> str:
            return payload[::-1]
        
        @self.register("doubled", "双重字符")
        def doubled(payload: str) -> str:
            return ''.join(c + c for c in payload)
    
    def apply(self, payload: str, tamper_list: List[str]) -> str:
        """
        应用多个 tamper scripts
        
        Args:
            payload: 原始 payload
            tamper_list: tamper script 名称列表
        
        Returns:
            经过 tamper 处理的 payload
        """
        result = payload
        for tamper_name in tamper_list:
            if tamper_name in self.scripts:
                result = self.scripts[tamper_name].apply(result)
            else:
                print(f"[Warning] Tamper script '{tamper_name}' not found")
        return result
    
    def list_scripts(self) -> Dict[str, str]:
        """列出所有可用的 tamper scripts"""
        return {name: script.description for name, script in self.scripts.items()}
    
    def get_script_info(self, name: str) -> str:
        """获取指定 tamper script 的详细信息"""
        if name in self.scripts:
            script = self.scripts[name]
            return f"{name}: {script.description}"
        return f"Tamper script '{name}' not found"


# 全局 tamper engine 实例
tamper_engine = TamperEngine()


if __name__ == "__main__":
    # 测试 tamper scripts
    test_payload = '<script>alert(1)</script>'
    
    print("Original payload:", test_payload)
    print("\nTesting tamper scripts:\n")
    
    for name, description in tamper_engine.list_scripts().items():
        result = tamper_engine.apply(test_payload, [name])
        print(f"{name:25s} | {result}")
    
    print("\n\nTesting combined tampers:")
    combined = tamper_engine.apply(test_payload, ['case_switch', 'space2comment'])
    print(f"case_switch + space2comment: {combined}")
