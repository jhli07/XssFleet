"""
Logging System for XSSMap
参考 sqlmap 的日志输出风格
"""

import sys
import time
from colorama import Fore, Style


class Logger:
    """
    日志系统 - 支持多种日志级别，类似 sqlmap
    """

    LEVELS = {
        0: 'QUIET',      # 静默模式，只输出关键信息
        1: 'CRITICAL',   # 仅严重错误
        2: 'ERROR',      # 错误信息
        3: 'WARNING',    # 警告信息
        4: 'INFO',       # 基本信息（默认）
        5: 'DEBUG',      # 调试信息
        6: 'TRACE'       # 详细追踪
    }

    def __init__(self, level: int = 4):
        """
        初始化日志系统

        Args:
            level: 日志级别 (0-6)
        """
        self.level = level
        self.start_time = time.time()
        self.payload_count = 0
        self.test_count = 0
        self.vulnerability_count = 0

    def _timestamp(self) -> str:
        """获取当前时间戳"""
        return time.strftime('%H:%M:%S')

    def _elapsed_time(self) -> str:
        """计算已过去的时间"""
        elapsed = time.time() - self.start_time
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        return f"{minutes:02d}:{seconds:02d}"

    def set_level(self, level: int):
        """设置日志级别"""
        if 0 <= level <= 6:
            self.level = level

    def critical(self, message: str):
        """严重错误级别 (level 1)"""
        if self.level >= 1:
            print(f"{self._timestamp()} {Fore.RED}[CRITICAL]{Style.RESET_ALL} {message}")

    def error(self, message: str):
        """错误级别 (level 2)"""
        if self.level >= 2:
            print(f"{self._timestamp()} {Fore.RED}[ERROR]{Style.RESET_ALL} {message}")

    def warning(self, message: str):
        """警告级别 (level 3)"""
        if self.level >= 3:
            print(f"{self._timestamp()} {Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")

    def info(self, message: str):
        """信息级别 (level 4) - 默认"""
        if self.level >= 4:
            print(f"{self._timestamp()} {Fore.CYAN}[INFO]{Style.RESET_ALL} {message}")

    def debug(self, message: str):
        """调试级别 (level 5)"""
        if self.level >= 5:
            print(f"{self._timestamp()} {Fore.BLUE}[DEBUG]{Style.RESET_ALL} {message}")

    def trace(self, message: str):
        """追踪级别 (level 6)"""
        if self.level >= 6:
            print(f"{self._timestamp()} {Fore.GREEN}[TRACE]{Style.RESET_ALL} {message}")

    def status(self, message: str):
        """状态信息 - 始终显示"""
        print(f"{self._timestamp()} {Fore.GREEN}[*]{Style.RESET_ALL} {message}")

    def success(self, message: str):
        """成功信息 - 始终显示"""
        print(f"{self._timestamp()} {Fore.GREEN}[+]{Style.RESET_ALL} {message}")

    def fail(self, message: str):
        """失败信息 - 始终显示"""
        print(f"{self._timestamp()} {Fore.RED}[-]{Style.RESET_ALL} {message}")

    def payload_test(self, param: str, payload: str, tampered: bool = False):
        """记录 Payload 测试"""
        self.payload_count += 1
        self.test_count += 1
        if self.level >= 5:
            tamper_mark = f" {Fore.MAGENTA}[TAMPERED]{Style.RESET_ALL}" if tampered else ""
            truncated_payload = payload[:50] + "..." if len(payload) > 50 else payload
            print(f"{self._timestamp()} {Fore.YELLOW}[PAYLOAD]{Style.RESET_ALL} Testing {param} with: {truncated_payload}{tamper_mark}")

    def payload_success(self, param: str, payload: str):
        """记录成功的 Payload"""
        self.vulnerability_count += 1
        safe_payload = payload.replace('"', '\\"')
        print(f"{self._timestamp()} {Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Found XSS in parameter '{param}' with payload: \"{safe_payload}\"")

    def param_start(self, param: str):
        """开始测试参数"""
        if self.level >= 4:
            print(f"{self._timestamp()} {Fore.CYAN}[PARAM]{Style.RESET_ALL} Testing parameter: {param}")

    def param_done(self, param: str, found: bool):
        """参数测试完成"""
        if self.level >= 4:
            status = f"{Fore.GREEN}VULNERABLE{Style.RESET_ALL}" if found else f"{Fore.BLUE}SAFE{Style.RESET_ALL}"
            print(f"{self._timestamp()} {Fore.CYAN}[PARAM]{Style.RESET_ALL} Finished testing {param} - {status}")

    def technique_start(self, technique: str):
        """开始使用某种技术"""
        if self.level >= 4:
            print(f"{self._timestamp()} {Fore.YELLOW}[TECHNIQUE]{Style.RESET_ALL} Using technique: {technique}")

    def http_request(self, method: str, url: str):
        """记录 HTTP 请求"""
        if self.level >= 6:
            print(f"{self._timestamp()} {Fore.BLUE}[HTTP]{Style.RESET_ALL} {method} {url}")

    def summary(self):
        """输出扫描摘要"""
        elapsed = self._elapsed_time()
        print(f"\n{self._timestamp()} {Fore.CYAN}[SUMMARY]{Style.RESET_ALL} Scan completed in {elapsed}")
        print(f"{self._timestamp()} {Fore.CYAN}[SUMMARY]{Style.RESET_ALL} Total tests: {self.test_count}")
        print(f"{self._timestamp()} {Fore.CYAN}[SUMMARY]{Style.RESET_ALL} Payloads tested: {self.payload_count}")
        print(f"{self._timestamp()} {Fore.CYAN}[SUMMARY]{Style.RESET_ALL} Vulnerabilities found: {self.vulnerability_count}")


# 全局日志实例
logger = Logger()


def set_log_level(level: int):
    """设置全局日志级别"""
    logger.set_level(level)


if __name__ == "__main__":
    # 测试日志系统
    test_logger = Logger(level=6)

    test_logger.status("Starting XSSMap scan")
    test_logger.info("Loading payloads...")
    test_logger.debug("Loaded 50 payloads")
    test_logger.param_start("q")
    test_logger.payload_test("q", "<script>alert(1)</script>")
    test_logger.payload_test("q", "<img src=x onerror=alert(1)>")
    test_logger.payload_success("q", "<script>alert(1)</script>")
    test_logger.param_done("q", True)
    test_logger.warning("Potential WAF detected")
    test_logger.info("Scan complete")
    test_logger.summary()
