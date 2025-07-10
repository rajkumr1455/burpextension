#!/usr/bin/env python3
"""
Burp Suite SSL Scan Extension with Color Formatting
A Python extension for Burp Suite that provides SSL/TLS scanning capabilities with colored output
"""

from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Font, Color
from java.awt.event import ActionListener
from javax.swing import (JPanel, JTextArea, JScrollPane, JButton, JLabel, 
                        JTextField, JComboBox, JCheckBox, JSplitPane, 
                        JMenuItem, JOptionPane, SwingUtilities, SwingWorker,
                        JTextPane, JTabbedPane)
from javax.swing.border import TitledBorder
from javax.swing.text import SimpleAttributeSet, StyleConstants, StyledDocument
import threading
import subprocess
import json
import os
import tempfile
import time
import re

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("SSL Scanner Pro")
        
        # Initialize UI components
        self._init_ui()
        
        # Register as tab and context menu factory
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        
        # Print startup message
        print("SSL Scanner Pro extension loaded successfully")
    
    def _init_ui(self):
        """Initialize the user interface"""
        # Main panel
        self._main_panel = JPanel(BorderLayout())
        
        # Create top panel for controls
        self._create_control_panel()
        
        # Create output panel
        self._create_output_panel()
        
        # Add panels to main panel
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setTopComponent(self._control_panel)
        split_pane.setBottomComponent(self._output_panel)
        split_pane.setDividerLocation(200)
        
        self._main_panel.add(split_pane, BorderLayout.CENTER)
    
    def _create_control_panel(self):
        """Create the control panel with scan options"""
        self._control_panel = JPanel(GridBagLayout())
        self._control_panel.setBorder(TitledBorder("SSL Scan Configuration"))
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        
        # Target input
        gbc.gridx = 0
        gbc.gridy = 0
        self._control_panel.add(JLabel("Target:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self._target_field = JTextField("", 30)
        self._target_field.setToolTipText("Enter target (host:port)")
        self._control_panel.add(self._target_field, gbc)
        
        # Scan type selection
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0
        self._control_panel.add(JLabel("Scan Type:"), gbc)
        
        gbc.gridx = 1
        scan_types = ["Quick Scan", "Full Scan", "Cipher Scan", "Protocol Scan", "Vulnerability Scan"]
        self._scan_type_combo = JComboBox(scan_types)
        self._control_panel.add(self._scan_type_combo, gbc)
        
        # Options checkboxes
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridwidth = 2
        self._json_output = JCheckBox("JSON Output", True)
        self._control_panel.add(self._json_output, gbc)
        
        gbc.gridy = 3
        self._verbose_output = JCheckBox("Verbose Output", False)
        self._control_panel.add(self._verbose_output, gbc)
        
        # Scan button
        gbc.gridy = 4
        gbc.gridwidth = 1
        gbc.gridx = 1
        gbc.anchor = GridBagConstraints.CENTER
        self._scan_button = JButton("Start SSL Scan", actionPerformed=self._start_scan)
        self._scan_button.setFont(Font(Font.SANS_SERIF, Font.BOLD, 12))
        self._control_panel.add(self._scan_button, gbc)
        
        # Clear button
        gbc.gridx = 0
        self._clear_button = JButton("Clear Output", actionPerformed=self._clear_output)
        self._control_panel.add(self._clear_button, gbc)
    
    def _create_output_panel(self):
        """Create the output panel for scan results"""
        self._output_panel = JPanel(BorderLayout())
        self._output_panel.setBorder(TitledBorder("Scan Results"))
        
        # Create tabbed pane for different views
        self._output_tabs = JTabbedPane()
        
        # Raw output tab with colored text
        self._output_pane = JTextPane()
        self._output_pane.setEditable(False)
        self._output_pane.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._output_pane.setBackground(Color(248, 248, 248))
        self._output_doc = self._output_pane.getStyledDocument()
        
        # Summary tab
        self._summary_area = JTextArea()
        self._summary_area.setEditable(False)
        self._summary_area.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._summary_area.setBackground(Color(255, 255, 255))
        
        # Add tabs
        raw_scroll = JScrollPane(self._output_pane)
        raw_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._output_tabs.addTab("Detailed Results", raw_scroll)
        
        summary_scroll = JScrollPane(self._summary_area)
        summary_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._output_tabs.addTab("Summary", summary_scroll)
        
        self._output_panel.add(self._output_tabs, BorderLayout.CENTER)
        
        # Initialize color styles
        self._init_color_styles()
    
    def _init_color_styles(self):
        """Initialize color styles for different types of output"""
        self._styles = {}
        
        # Default style
        self._styles['default'] = SimpleAttributeSet()
        StyleConstants.setForeground(self._styles['default'], Color.BLACK)
        
        # Success/OK style (green)
        self._styles['success'] = SimpleAttributeSet()
        StyleConstants.setForeground(self._styles['success'], Color(0, 128, 0))
        StyleConstants.setBold(self._styles['success'], True)
        
        # Warning style (orange/yellow)
        self._styles['warning'] = SimpleAttributeSet()
        StyleConstants.setForeground(self._styles['warning'], Color(255, 140, 0))
        StyleConstants.setBold(self._styles['warning'], True)
        
        # Error/Vulnerable style (red)
        self._styles['error'] = SimpleAttributeSet()
        StyleConstants.setForeground(self._styles['error'], Color(220, 20, 60))
        StyleConstants.setBold(self._styles['error'], True)
        
        # Info style (blue)
        self._styles['info'] = SimpleAttributeSet()
        StyleConstants.setForeground(self._styles['info'], Color(0, 100, 200))
        StyleConstants.setBold(self._styles['info'], True)
        
        # Header style
        self._styles['header'] = SimpleAttributeSet()
        StyleConstants.setForeground(self._styles['header'], Color(75, 0, 130))
        StyleConstants.setBold(self._styles['header'], True)
        StyleConstants.setFontSize(self._styles['header'], 13)
        
        # Vulnerability style (bright red)
        self._styles['vulnerability'] = SimpleAttributeSet()
        StyleConstants.setForeground(self._styles['vulnerability'], Color(255, 0, 0))
        StyleConstants.setBold(self._styles['vulnerability'], True)
        StyleConstants.setUnderline(self._styles['vulnerability'], True)
        
        # Weak cipher style
        self._styles['weak'] = SimpleAttributeSet()
        StyleConstants.setForeground(self._styles['weak'], Color(255, 69, 0))
        StyleConstants.setBold(self._styles['weak'], True)
    
    def _start_scan(self, event):
        """Start the SSL scan"""
        target = self._target_field.getText().strip()
        if not target:
            JOptionPane.showMessageDialog(self._main_panel, 
                                        "Please enter a target (host:port)", 
                                        "Error", 
                                        JOptionPane.ERROR_MESSAGE)
            return
        
        # Disable scan button during scan
        self._scan_button.setEnabled(False)
        self._scan_button.setText("Scanning...")
        
        # Clear previous output
        self._output_pane.setText("")
        self._summary_area.setText("")
        
        # Start scan in background thread
        scan_worker = SSLScanWorker(self, target)
        scan_worker.execute()
    
    def _clear_output(self, event):
        """Clear the output area"""
        self._output_pane.setText("")
        self._summary_area.setText("")
    
    def _append_output(self, text):
        """Append text to output area with color formatting (thread-safe)"""
        SwingUtilities.invokeLater(lambda: self._append_colored_text(text))
    
    def _append_colored_text(self, text):
        """Append text with appropriate coloring based on content"""
        # Remove ANSI color codes and parse content
        clean_text = self._remove_ansi_codes(text)
        style = self._determine_text_style(clean_text)
        
        try:
            self._output_doc.insertString(self._output_doc.getLength(), clean_text + "\n", style)
            # Auto-scroll to bottom
            self._output_pane.setCaretPosition(self._output_doc.getLength())
        except Exception as e:
            print("Error appending text: " + str(e))
    
    def _remove_ansi_codes(self, text):
        """Remove ANSI color codes from text"""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def _determine_text_style(self, text):
        """Determine the appropriate style based on text content"""
        text_lower = text.lower()
        
        # Check for vulnerabilities first (highest priority)
        vulnerabilities = ['lucky13', 'heartbleed', 'poodle', 'beast', 'crime', 'breach', 
                          'freak', 'drown', 'logjam', 'sweet32', 'ticketbleed', 'robot']
        
        for vuln in vulnerabilities:
            if vuln in text_lower and ('vulnerable' in text_lower or 'affected' in text_lower):
                return self._styles['vulnerability']
        
        # Check for success indicators
        if any(indicator in text_lower for indicator in ['not vulnerable (ok)', 'not offered (ok)', 
                                                        'offered (ok)', 'supported (ok)', 'ok via']):
            return self._styles['success']
        
        # Check for warnings
        if any(indicator in text_lower for indicator in ['expires <', 'weak', 'deprecated', 
                                                        'insecure', 'none httponly']):
            return self._styles['warning']
        
        # Check for errors/vulnerabilities
        if any(indicator in text_lower for indicator in ['vulnerable', 'failed', 'error', 
                                                        'critical', 'high risk']):
            return self._styles['error']
        
        # Check for headers/sections
        if text.startswith('Testing ') or text.startswith('Running ') or '====' in text:
            return self._styles['header']
        
        # Check for weak ciphers
        weak_ciphers = ['rc4', 'des', 'md5', 'null', 'export', 'adh', 'aecdh']
        if any(cipher in text_lower for cipher in weak_ciphers):
            return self._styles['weak']
        
        # Check for info
        if any(indicator in text_lower for indicator in ['protocol', 'cipher', 'certificate', 
                                                        'grade', 'rating']):
            return self._styles['info']
        
        return self._styles['default']
    
    def _scan_complete(self):
        """Called when scan is complete"""
        SwingUtilities.invokeLater(lambda: (
            self._scan_button.setEnabled(True),
            self._scan_button.setText("Start SSL Scan"),
            self._generate_summary()
        ))
    
    def _generate_summary(self):
        """Generate a summary of scan results"""
        try:
            # Get the full scan output
            full_text = self._output_pane.getText()
            
            summary_lines = []
            summary_lines.append("=== SSL SCAN SUMMARY ===\n")
            
            # Extract key information
            target = self._extract_target_info(full_text)
            if target:
                summary_lines.append("[TARGET] " + target)
            
            # Protocol support
            protocols = self._extract_protocols(full_text)
            if protocols:
                summary_lines.append("\n[PROTOCOLS] Supported:")
                for protocol in protocols:
                    summary_lines.append("  " + protocol)
            
            # Certificate info
            cert_info = self._extract_certificate_info(full_text)
            if cert_info:
                summary_lines.append("\n[CERTIFICATE]")
                for info in cert_info:
                    summary_lines.append("  " + info)
            
            # Vulnerabilities
            vulnerabilities = self._extract_vulnerabilities(full_text)
            if vulnerabilities:
                summary_lines.append("\n[VULNERABILITIES] Found:")
                for vuln in vulnerabilities:
                    summary_lines.append("  " + vuln)
            else:
                summary_lines.append("\n[VULNERABILITIES] No Major Issues Detected")
            
            # Overall grade
            grade = self._extract_grade(full_text)
            if grade:
                summary_lines.append("\n[GRADE] " + grade)
            
            # Recommendations
            recommendations = self._generate_recommendations(full_text)
            if recommendations:
                summary_lines.append("\n[RECOMMENDATIONS]")
                for rec in recommendations:
                    summary_lines.append("  * " + rec)
            
            self._summary_area.setText("\n".join(summary_lines))
            
        except Exception as e:
            self._summary_area.setText("Error generating summary: " + str(e))
    
    def _extract_target_info(self, text):
        """Extract target information"""
        lines = text.split('\n')
        for line in lines:
            if 'Starting SSL scan for:' in line:
                return line.split(':', 1)[1].strip()
        return None
    
    def _extract_protocols(self, text):
        """Extract supported protocols"""
        protocols = []
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if 'offered (OK)' in line and ('TLS' in line or 'SSL' in line):
                if 'SSLv2' in line:
                    protocols.append("CRITICAL: SSLv2 - INSECURE")
                elif 'SSLv3' in line:
                    protocols.append("HIGH RISK: SSLv3 - INSECURE")
                elif 'TLS 1.3' in line:
                    protocols.append("EXCELLENT: TLS 1.3")
                elif 'TLS 1.2' in line:
                    protocols.append("GOOD: TLS 1.2")
                elif 'TLS 1.1' in line:
                    protocols.append("DEPRECATED: TLS 1.1")
                elif 'TLS 1' in line:
                    protocols.append("DEPRECATED: TLS 1.0")
        return protocols
    
    def _extract_certificate_info(self, text):
        """Extract certificate information"""
        cert_info = []
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if 'Common Name (CN)' in line:
                cn = line.split(')', 1)[1].strip() if ')' in line else line.split(':', 1)[1].strip()
                cert_info.append("CN: " + cn)
            elif 'Certificate Validity' in line:
                if 'expires <' in line:
                    cert_info.append("WARNING: Certificate expires soon!")
                else:
                    cert_info.append("Certificate validity OK")
            elif 'Overall Grade' in line:
                grade = line.split()[-1]
                cert_info.append("Grade: " + grade)
        return cert_info
    
    def _extract_vulnerabilities(self, text):
        """Extract vulnerability information"""
        vulnerabilities = []
        lines = text.split('\n')
        
        vuln_checks = {
            'Heartbleed': 'heartbleed',
            'POODLE': 'poodle', 
            'BEAST': 'beast',
            'CRIME': 'crime',
            'BREACH': 'breach',
            'FREAK': 'freak',
            'DROWN': 'drown',
            'LOGJAM': 'logjam',
            'SWEET32': 'sweet32',
            'LUCKY13': 'lucky13',
            'ROBOT': 'robot',
            'Ticketbleed': 'ticketbleed'
        }
        
        for line in lines:
            line_lower = line.lower()
            for vuln_name, vuln_key in vuln_checks.items():
                if vuln_key in line_lower:
                    if 'vulnerable' in line_lower and 'not vulnerable' not in line_lower:
                        vulnerabilities.append("CRITICAL: " + vuln_name + " - VULNERABLE")
        
        # Check for weak protocols
        if 'sslv2' in text.lower() and 'offered (ok)' in text.lower():
            vulnerabilities.append("CRITICAL: SSLv2 enabled")
        if 'sslv3' in text.lower() and 'offered (ok)' in text.lower():
            vulnerabilities.append("HIGH: SSLv3 enabled")
            
        return vulnerabilities
    
    def _extract_grade(self, text):
        """Extract overall security grade"""
        lines = text.split('\n')
        for line in lines:
            if 'Overall Grade' in line:
                grade = line.split()[-1]
                if grade == 'A+':
                    return "A+ (Excellent)"
                elif grade == 'A':
                    return "A (Very Good)"
                elif grade == 'B':
                    return "B (Good)"
                elif grade == 'C':
                    return "C (Fair)"
                elif grade in ['D', 'E', 'F']:
                    return grade + " (Poor - Needs Attention)"
                else:
                    return grade
        return None
    
    def _generate_recommendations(self, text):
        """Generate security recommendations based on scan results"""
        recommendations = []
        text_lower = text.lower()
        
        # Check for certificate expiry
        if 'expires <' in text_lower:
            recommendations.append("Renew SSL certificate before expiration")
        
        # Check for weak protocols
        if 'sslv2' in text_lower and 'offered' in text_lower:
            recommendations.append("URGENT: Disable SSLv2 protocol (critical security risk)")
        if 'sslv3' in text_lower and 'offered' in text_lower:
            recommendations.append("Disable SSLv3 protocol (POODLE vulnerability)")
        
        # Check for missing security headers
        if 'hsts' not in text_lower or 'strict transport security' not in text_lower:
            recommendations.append("Implement HTTP Strict Transport Security (HSTS)")
        
        # Check for weak ciphers
        if 'rc4' in text_lower and 'offered' in text_lower:
            recommendations.append("Disable RC4 cipher suites")
        if 'des' in text_lower and 'offered' in text_lower:
            recommendations.append("Disable DES cipher suites")
        
        # Check for missing OCSP stapling
        if 'ocsp stapling' in text_lower and 'not offered' in text_lower:
            recommendations.append("Enable OCSP stapling for better performance")
        
        return recommendations
    
    def getTabCaption(self):
        """Return the tab caption"""
        return "SSL Scanner"
    
    def getUiComponent(self):
        """Return the UI component"""
        return self._main_panel
    
    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_items = []
        
        # Only show menu for HTTP requests
        if invocation.getInvocationContext() in [
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE
        ]:
            # Get selected messages
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                # Create menu item
                menu_item = JMenuItem("SSL Scan Target")
                menu_item.addActionListener(SSLScanMenuListener(self, messages[0]))
                menu_items.append(menu_item)
        
        return menu_items
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages (IHttpListener implementation)"""
        # This can be used to automatically detect HTTPS targets
        pass


class SSLScanWorker(SwingWorker):
    """Background worker for SSL scanning"""
    
    def __init__(self, extender, target):
        self._extender = extender
        self._target = target
    
    def doInBackground(self):
        """Perform the SSL scan in background"""
        try:
            self._extender._append_output("Starting SSL scan for: " + self._target)
            self._extender._append_output("=" * 50)
            
            # Parse target
            if ":" in self._target:
                host, port = self._target.rsplit(":", 1)
                try:
                    port = int(port)
                except ValueError:
                    port = 443
            else:
                host = self._target
                port = 443
            
            # Perform different types of scans based on selection
            scan_type = self._extender._scan_type_combo.getSelectedItem()
            
            if scan_type == "Quick Scan":
                self._quick_scan(host, port)
            elif scan_type == "Full Scan":
                self._full_scan(host, port)
            elif scan_type == "Cipher Scan":
                self._cipher_scan(host, port)
            elif scan_type == "Protocol Scan":
                self._protocol_scan(host, port)
            elif scan_type == "Vulnerability Scan":
                self._vulnerability_scan(host, port)
            
        except Exception as e:
            self._extender._append_output("Error during scan: " + str(e))
        finally:
            self._extender._scan_complete()
    
    def _quick_scan(self, host, port):
        """Perform a quick SSL scan"""
        self._extender._append_output("Performing quick SSL scan...")
        
        # Try to use testssl.sh if available
        if self._run_testssl(host, port, ["--fast"]):
            return
        
        # Fallback to basic SSL info gathering
        self._basic_ssl_scan(host, port)
    
    def _full_scan(self, host, port):
        """Perform a comprehensive SSL scan"""
        self._extender._append_output("Performing full SSL scan...")
        
        if self._run_testssl(host, port, ["--full"]):
            return
        
        # Fallback scan
        self._basic_ssl_scan(host, port)
    
    def _cipher_scan(self, host, port):
        """Scan for supported ciphers"""
        self._extender._append_output("Scanning supported ciphers...")
        
        if self._run_testssl(host, port, ["--cipher-per-proto"]):
            return
        
        self._basic_ssl_scan(host, port)
    
    def _protocol_scan(self, host, port):
        """Scan for supported protocols"""
        self._extender._append_output("Scanning supported protocols...")
        
        if self._run_testssl(host, port, ["--protocols"]):
            return
        
        self._basic_ssl_scan(host, port)
    
    def _vulnerability_scan(self, host, port):
        """Scan for SSL vulnerabilities"""
        self._extender._append_output("Scanning for SSL vulnerabilities...")
        
        if self._run_testssl(host, port, ["--vulnerabilities"]):
            return
        
        self._basic_ssl_scan(host, port)
    
    def _run_testssl(self, host, port, args):
        """Try to run testssl.sh"""
        try:
            # Look for testssl.sh in common locations
            testssl_paths = [
                "./testssl.sh/testssl.sh",
                "./burp-testssl-extension/resources/testssl/testssl.sh",
                "/usr/local/bin/testssl.sh",
                "/usr/bin/testssl.sh",
                "testssl.sh"
            ]
            
            testssl_path = None
            for path in testssl_paths:
                if os.path.exists(path):
                    testssl_path = path
                    break
            
            if not testssl_path:
                self._extender._append_output("testssl.sh not found, using basic scan")
                return False
            
            # Build command
            cmd = [testssl_path] + args
            if self._extender._json_output.isSelected():
                cmd.append("--jsonfile-pretty")
                cmd.append("-")
            if self._extender._verbose_output.isSelected():
                cmd.append("--verbose")
            
            cmd.append(host + ":" + str(port))
            
            self._extender._append_output("Running: " + " ".join(cmd))
            
            # Execute command
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.STDOUT, 
                                     universal_newlines=True)
            
            # Read output line by line
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self._extender._append_output(output.strip())
            
            return True
            
        except Exception as e:
            self._extender._append_output("Failed to run testssl.sh: " + str(e))
            return False
    
    def _basic_ssl_scan(self, host, port):
        """Basic SSL scan using Python libraries"""
        try:
            import ssl
            import socket
            
            self._extender._append_output("Performing basic SSL analysis...")
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate info
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    self._extender._append_output("SSL/TLS Version: " + str(version))
                    self._extender._append_output("Cipher: " + str(cipher))
                    
                    if cert:
                        self._extender._append_output("Certificate Subject: " + str(cert.get('subject', 'N/A')))
                        self._extender._append_output("Certificate Issuer: " + str(cert.get('issuer', 'N/A')))
                        self._extender._append_output("Certificate Valid From: " + str(cert.get('notBefore', 'N/A')))
                        self._extender._append_output("Certificate Valid Until: " + str(cert.get('notAfter', 'N/A')))
                        
                        # Check for SAN
                        san = cert.get('subjectAltName', [])
                        if san:
                            self._extender._append_output("Subject Alternative Names:")
                            for name_type, name_value in san:
                                self._extender._append_output("  " + name_type + ": " + name_value)
        
        except Exception as e:
            self._extender._append_output("Basic SSL scan failed: " + str(e))


class SSLScanMenuListener(ActionListener):
    """Action listener for context menu"""
    
    def __init__(self, extender, message):
        self._extender = extender
        self._message = message
    
    def actionPerformed(self, event):
        """Handle menu item click"""
        # Get target from HTTP service
        service = self._message.getHttpService()
        host = service.getHost()
        port = service.getPort()
        
        # Set target in UI and switch to SSL Scanner tab
        self._extender._target_field.setText(host + ":" + str(port))
        
        # Show message to user
        JOptionPane.showMessageDialog(None, 
                                    "Target set to: " + host + ":" + str(port) + "\nSwitch to SSL Scanner tab to run scan",
                                    "SSL Scanner", 
                                    JOptionPane.INFORMATION_MESSAGE)