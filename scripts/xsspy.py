#!/usr/bin/env python3
"""
XSSPY - Advanced Cross-Site Scripting Vulnerability Scanner
Author: Zishan Ahamed Thandar
A comprehensive security tool for identifying XSS vulnerabilities through
automated website traversal and intelligent payload injection.
"""

import mechanize
import sys
import http.client
import argparse
import logging
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Set, Optional, Tuple
import time
import re


class ColorFormatter:
    """ANSI color codes for terminal output formatting"""
    
    BLUE = '\033[94m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    @classmethod
    def format(cls, message: str, color: str, bold: bool = False) -> str:
        """Format message with specified color and optional bold styling"""
        formatted = f"{color}{message}{cls.END}"
        if bold:
            formatted = f"{cls.BOLD}{formatted}"
        return formatted


class XSSScanner:
    """
    Main scanner class for detecting Cross-Site Scripting vulnerabilities
    """
    
    def __init__(self, target_url: str, comprehensive_scan: bool = False, 
                 verbose: bool = False, cookies: List[str] = None):
        """
        Initialize the XSS scanner with configuration parameters
        
        Args:
            target_url: Base URL to scan
            comprehensive_scan: Enable deep website traversal
            verbose: Enable detailed logging
            cookies: List of cookies for authenticated scanning
        """
        self.target_url = self._normalize_url(target_url)
        self.comprehensive_scan = comprehensive_scan
        self.verbose = verbose
        self.cookies = cookies or []
        
        # XSS payloads categorized by injection type
        self.payloads = {
            'html_context': [
                '<svg onload="alert(1)">',
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>'
            ],
            'attribute_context': [
                '" onmouseover="alert(1)"',
                "' onfocus='alert(1)'",
                ' autofocus onfocus=alert(1)//'
            ],
            'javascript_context': [
                'javascript:alert(1)',
                'JaVaScRiPt:alert(1)',
                '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)'
            ]
        }
        
        # File extensions to exclude from scanning
        self.blacklisted_extensions = {
            '.png', '.jpg', '.jpeg', '.mp3', '.mp4', '.avi', 
            '.gif', '.svg', '.pdf', '.css', '.woff', '.woff2'
        }
        
        self.vulnerabilities: List[Dict] = []
        self.discovered_urls: Set[str] = set()
        
        self._initialize_browser()
        self._setup_logging()
        
    def _normalize_url(self, url: str) -> str:
        """Ensure URL has proper scheme format"""
        if not url.startswith(('http://', 'https://')):
            return f'https://{url}'
        return url
        
    def _initialize_browser(self):
        """Configure mechanize browser instance with appropriate settings"""
        self.browser = mechanize.Browser()
        
        # Set realistic browser headers
        self.browser.addheaders = [
            ('User-Agent', 
             'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
             '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'),
            ('Accept', 
             'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'),
            ('Accept-Language', 'en-US,en;q=0.5'),
            ('Connection', 'keep-alive')
        ]
        
        # Browser configuration
        self.browser.set_handle_robots(False)
        self.browser.set_handle_refresh(False)
        self.browser.set_handle_redirect(True)
        self.browser.set_handle_referer(True)
        
    def _setup_logging(self):
        """Configure logging based on verbosity settings"""
        self.logger = logging.getLogger('XSSScanner')
        handler = logging.StreamHandler()
        
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        log_level = logging.DEBUG if self.verbose else logging.INFO
        self.logger.setLevel(log_level)
        
    def log(self, message: str, level: str = 'info', color: str = None):
        """Enhanced logging with color support"""
        color_map = {
            'info': ColorFormatter.GREEN,
            'warning': ColorFormatter.YELLOW,
            'error': ColorFormatter.RED,
            'debug': ColorFormatter.BLUE
        }
        
        color_code = color or color_map.get(level, ColorFormatter.GREEN)
        formatted_msg = ColorFormatter.format(message, color_code, bold=True)
        
        if level == 'debug':
            self.logger.debug(formatted_msg)
        elif level == 'warning':
            self.logger.warning(formatted_msg)
        elif level == 'error':
            self.logger.error(formatted_msg)
        else:
            self.logger.info(formatted_msg)

    def display_banner(self):
        """Display tool banner and information"""
        banner = """
                                        
+++ XSSPy Advanced v5.0 +++
Enhanced Security Scanner
Zishan Ahamed Thandar
https://ZishanAdThandar.GitHub.io

        """
        
        usage = """
Usage: 
Basic scan: xsspy -u https://example.com
Comprehensive: xsspy -u example.com -e
Verbose output: xsspy -u example.com -v
With cookies: xsspy -u example.com -c "session=abc" "user=123"
        """
        
        description = """
Description: 
XSSPy is an advanced Python tool for detecting Cross-Site Scripting 
vulnerabilities. It performs comprehensive website traversal, 
intelligent payload injection, and detailed vulnerability reporting.
        """
        
        print(ColorFormatter.format(banner, ColorFormatter.RED, bold=True))
        print(ColorFormatter.format(usage, ColorFormatter.YELLOW, bold=True))
        print(ColorFormatter.format(description, ColorFormatter.BLUE, bold=True))

    def should_scan_url(self, url: str) -> bool:
        """
        Determine if a URL should be included in scanning
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if URL should be scanned
        """
        # Check if URL belongs to target domain
        if self.target_url not in url:
            return False
            
        # Check for blacklisted file extensions
        parsed_url = urlparse(url)
        path_lower = parsed_url.path.lower()
        
        if any(path_lower.endswith(ext) for ext in self.blacklisted_extensions):
            self.log(f"Skipping blacklisted URL: {url}", 'debug')
            return False
            
        # Additional URL validation can be added here
        return True

    def discover_urls(self) -> Set[str]:
        """
        Perform website traversal to discover all accessible URLs
        
        Returns:
            Set of discovered URLs
        """
        self.log("Starting website URL discovery...", 'info')
        
        urls_to_visit = {self.target_url}
        discovered_urls = set()
        max_urls = 1000 if self.comprehensive_scan else 100
        
        try:
            while urls_to_visit and len(discovered_urls) < max_urls:
                current_url = urls_to_visit.pop()
                
                if current_url in discovered_urls:
                    continue
                    
                try:
                    self.log(f"Crawling: {current_url}", 'debug')
                    self.browser.open(current_url)
                    discovered_urls.add(current_url)
                    
                    # Extract and process links from current page
                    for link in self.browser.links():
                        absolute_url = urljoin(current_url, link.absolute_url)
                        
                        if (self.should_scan_url(absolute_url) and 
                            absolute_url not in discovered_urls):
                            urls_to_visit.add(absolute_url)
                            
                except Exception as e:
                    self.log(f"Error crawling {current_url}: {str(e)}", 'debug')
                    continue
                    
        except KeyboardInterrupt:
            self.log("URL discovery interrupted by user", 'warning')
            
        self.log(f"Discovered {len(discovered_urls)} URLs for scanning", 'info')
        return discovered_urls

    def test_form_vulnerability(self, form, form_url: str) -> bool:
        """
        Test a single form for XSS vulnerabilities
        
        Args:
            form: Mechanize form object
            form_url: URL where form is located
            
        Returns:
            bool: True if vulnerability found
        """
        vulnerability_found = False
        
        try:
            self.browser.select_form(nr=list(self.browser.forms()).index(form))
            
            for control in form.controls:
                if control.type in ['text', 'textarea', 'password', 'search']:
                    self.log(f"Testing parameter: {control.name}", 'debug')
                    
                    for payload_category, payloads in self.payloads.items():
                        for payload in payloads:
                            if self._test_payload(control, payload, form_url):
                                vulnerability_found = True
                                # Continue testing other payloads even if one works
                                
        except Exception as e:
            self.log(f"Error testing form: {str(e)}", 'debug')
            
        return vulnerability_found

    def _test_payload(self, control, payload: str, form_url: str) -> bool:
        """
        Test a specific payload against a form control
        
        Args:
            control: Form control to test
            payload: XSS payload to inject
            form_url: URL of the form
            
        Returns:
            bool: True if vulnerability is detected
        """
        try:
            # Store original value
            original_value = control.value
            
            # Inject payload and submit form
            control.value = payload
            response = self.browser.submit()
            response_text = response.read().decode('utf-8', errors='ignore')
            
            # Check if payload is reflected in response
            if payload in response_text:
                vulnerability = {
                    'url': form_url,
                    'parameter': control.name,
                    'payload': payload,
                    'type': 'Reflected XSS',
                    'severity': 'High'
                }
                self.vulnerabilities.append(vulnerability)
                
                self.log(
                    f"XSS VULNERABILITY FOUND: {form_url} - Parameter: {control.name}",
                    'error'
                )
                self.log(f"Payload: {payload}", 'error')
                
                return True
                
        except Exception as e:
            self.log(f"Error testing payload: {str(e)}", 'debug')
        finally:
            # Restore original form state
            try:
                self.browser.back()
                if hasattr(control, 'value'):
                    control.value = original_value
            except:
                pass
                
        return False

    def scan_urls(self, urls: Set[str]):
        """
        Scan discovered URLs for XSS vulnerabilities
        
        Args:
            urls: Set of URLs to scan
        """
        self.log("Starting XSS vulnerability scanning...", 'info')
        
        for url in urls:
            self.log(f"Scanning URL: {url}", 'debug')
            
            try:
                self.browser.open(url)
                
                # Test all forms on the page
                forms = list(self.browser.forms())
                if forms:
                    self.log(f"Found {len(forms)} forms on {url}", 'debug')
                    
                    for form in forms:
                        self.test_form_vulnerability(form, url)
                else:
                    self.log(f"No forms found on {url}", 'debug')
                    
            except Exception as e:
                self.log(f"Error scanning {url}: {str(e)}", 'debug')

    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        if not self.vulnerabilities:
            self.log("No XSS vulnerabilities found!", 'info')
            return
            
        self.log("\n" + "="*60, 'info')
        self.log("XSS VULNERABILITY REPORT", 'info')
        self.log("="*60, 'info')
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            self.log(f"\n{i}. Vulnerability Details:", 'warning')
            self.log(f"   URL: {vuln['url']}", 'warning')
            self.log(f"   Parameter: {vuln['parameter']}", 'warning')
            self.log(f"   Type: {vuln['type']}", 'warning')
            self.log(f"   Severity: {vuln['severity']}", 'warning')
            self.log(f"   Payload: {vuln['payload']}", 'warning')
            
        self.log(f"\nTotal vulnerabilities found: {len(self.vulnerabilities)}", 'error')

    def run_scan(self):
        """Execute complete XSS scanning workflow"""
        start_time = time.time()
        
        try:
            # Display banner
            self.display_banner()
            
            # Configure cookies if provided
            if self.cookies:
                self.log("Configuring cookies...", 'info')
                for cookie in self.cookies:
                    self.browser.set_cookie(cookie)
                    
            # Discover URLs
            discovered_urls = self.discover_urls()
            
            if not discovered_urls:
                self.log("No URLs discovered for scanning", 'error')
                return
                
            # Perform vulnerability scanning
            self.scan_urls(discovered_urls)
            
            # Generate final report
            self.generate_report()
            
        except KeyboardInterrupt:
            self.log("Scan interrupted by user", 'warning')
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", 'error')
        finally:
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds", 'info')


def main():
    """Main entry point for the XSS scanner"""
    parser = argparse.ArgumentParser(
        description='Advanced XSS Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL to scan (e.g., https://example.com)'
    )
    
    parser.add_argument(
        '-e', '--comprehensive',
        action='store_true',
        help='Enable comprehensive scanning (deeper traversal)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output for debugging'
    )
    
    parser.add_argument(
        '-c', '--cookies',
        nargs='+',
        help='Cookies for authenticated scanning (space-separated)',
        default=[]
    )
    
    args = parser.parse_args()
    
    # Initialize and run scanner
    scanner = XSSScanner(
        target_url=args.url,
        comprehensive_scan=args.comprehensive,
        verbose=args.verbose,
        cookies=args.cookies
    )
    
    scanner.run_scan()


if __name__ == '__main__':
    main()
