#!/usr/bin/env python3
"""
Dynamic Triage Checklist Generator
Generates component-specific triage checklists based on actual SBOM contents and vulnerabilities found.
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class ConfigQuestion:
    """A configuration question for triage"""
    config_option: str
    description: str
    affects_cves: List[str]
    question_type: str = "yes_no"  # yes_no, value, text


@dataclass
class InterfaceQuestion:
    """An interface question for triage"""
    interface: str
    description: str
    relevant_for: List[str]  # component types this applies to


# Component-specific configuration databases
COMPONENT_CONFIG_DB: Dict[str, List[ConfigQuestion]] = {
    "mbedtls": [
        ConfigQuestion("MBEDTLS_SSL_PROTO_DTLS", "DTLS protocol support", ["CVE-2022-35409", "CVE-2022-46393"]),
        ConfigQuestion("MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE", "DTLS port reuse", ["CVE-2022-35409"]),
        ConfigQuestion("MBEDTLS_SSL_DTLS_CONNECTION_ID", "DTLS Connection ID", ["CVE-2022-46393"]),
        ConfigQuestion("MBEDTLS_SSL_IN_CONTENT_LEN", "Input content length (vulnerable if < 258)", ["CVE-2022-35409"], "value"),
        ConfigQuestion("MBEDTLS_SSL_PROTO_TLS1_3", "TLS 1.3 support", ["CVE-2024-45159", "CVE-2024-28755"]),
        ConfigQuestion("MBEDTLS_PSA_CRYPTO_C", "PSA Crypto enabled", ["CVE-2024-45158"]),
        ConfigQuestion("LMS signatures used?", "Post-quantum LMS signatures", ["CVE-2025-49600", "CVE-2025-49601"]),
        ConfigQuestion("Hardware hash accelerator?", "HW crypto acceleration", ["CVE-2025-49600"]),
        ConfigQuestion("X.509 functions called directly?", "Direct X.509 API usage", ["CVE-2025-47917", "CVE-2024-23775"]),
        ConfigQuestion("mbedtls_ssl_set_hostname() called?", "Hostname verification for TLS client", ["CVE-2025-27809"]),
        ConfigQuestion("Session resumption/reset used?", "SSL session management", ["CVE-2023-52353", "CVE-2021-44732"]),
        ConfigQuestion("PEM parsing of untrusted input?", "PEM file parsing", ["CVE-2025-52497"]),
    ],
    "openssl": [
        ConfigQuestion("OpenSSL version branch", "1.0.x, 1.1.x, or 3.x", [], "text"),
        ConfigQuestion("FIPS mode enabled?", "FIPS 140-2/3 compliance mode", []),
        ConfigQuestion("TLS 1.3 enabled?", "TLS 1.3 protocol support", []),
        ConfigQuestion("Certificate verification enabled?", "X.509 cert validation", []),
        ConfigQuestion("Engine/Provider plugins used?", "Custom crypto providers", []),
        ConfigQuestion("DTLS enabled?", "Datagram TLS support", []),
    ],
    "wolfssl": [
        ConfigQuestion("WOLFSSL_DTLS", "DTLS protocol support", []),
        ConfigQuestion("WOLFSSL_TLS13", "TLS 1.3 support", []),
        ConfigQuestion("HAVE_FIPS", "FIPS mode enabled", []),
        ConfigQuestion("WOLFSSL_CERT_GEN", "Certificate generation", []),
        ConfigQuestion("Hardware crypto acceleration?", "HW crypto offload", []),
    ],
    "freertos": [
        ConfigQuestion("configUSE_TICK_HOOK", "Tick hook enabled", []),
        ConfigQuestion("configCHECK_FOR_STACK_OVERFLOW", "Stack overflow checking", []),
        ConfigQuestion("configUSE_MALLOC_FAILED_HOOK", "Malloc failure hook", []),
        ConfigQuestion("configASSERT defined?", "Assert macro configured", []),
        ConfigQuestion("MPU support enabled?", "Memory Protection Unit", []),
        ConfigQuestion("FreeRTOS+TCP used?", "TCP/IP stack", []),
    ],
    "safertos": [
        ConfigQuestion("Safety certification level", "SIL/ASIL rating", [], "text"),
        ConfigQuestion("MPU enabled?", "Memory Protection Unit", []),
        ConfigQuestion("Stack monitoring enabled?", "Runtime stack checks", []),
        ConfigQuestion("Privileged/unprivileged tasks?", "Task privilege separation", []),
    ],
    "zephyr": [
        ConfigQuestion("CONFIG_NET_TCP", "TCP networking enabled", []),
        ConfigQuestion("CONFIG_NET_SOCKETS", "BSD sockets API", []),
        ConfigQuestion("CONFIG_MBEDTLS", "mbedTLS integration", []),
        ConfigQuestion("CONFIG_BT", "Bluetooth enabled", []),
        ConfigQuestion("CONFIG_USERSPACE", "User mode enabled", []),
    ],
    "linux": [
        ConfigQuestion("Kernel version", "Linux kernel version", [], "text"),
        ConfigQuestion("SELinux/AppArmor enabled?", "Mandatory Access Control", []),
        ConfigQuestion("Secure boot enabled?", "UEFI Secure Boot", []),
        ConfigQuestion("Kernel module signing?", "Module signature verification", []),
        ConfigQuestion("ASLR enabled?", "Address Space Layout Randomization", []),
    ],
    "shibboleth-sp": [
        ConfigQuestion("Deployment platform", "Windows / Linux / Other", [], "text"),
        ConfigQuestion("ODBC replay cache configured?", "SQL database for replay cache", ["CVE-2025-9943"]),
        ConfigQuestion("Installation path", "Default C:\\opt or custom", ["CVE-2023-22947"], "text"),
        ConfigQuestion("SAML assertion validation?", "Signature verification", []),
    ],
    # Generic fallback for unknown components
    "_default": [
        ConfigQuestion("Component version confirmed?", "Version matches SBOM", []),
        ConfigQuestion("Component actively maintained?", "Vendor support status", []),
        ConfigQuestion("Security patches available?", "Patch availability", []),
        ConfigQuestion("Network accessible?", "Exposed to network", []),
        ConfigQuestion("Processes untrusted input?", "Handles external data", []),
    ],
}

# Interface types relevant to different component categories
INTERFACE_DB: Dict[str, List[InterfaceQuestion]] = {
    "network": [
        InterfaceQuestion("Ethernet (DoIP)", "Diagnostics over IP", ["library", "firmware"]),
        InterfaceQuestion("Ethernet (SomeIP)", "Service-oriented middleware", ["library", "firmware"]),
        InterfaceQuestion("WiFi", "Wireless LAN", ["library", "firmware", "operating-system"]),
        InterfaceQuestion("Cellular/V2X", "Vehicle-to-everything", ["library", "firmware"]),
        InterfaceQuestion("Bluetooth/BLE", "Bluetooth connectivity", ["library", "firmware"]),
    ],
    "automotive": [
        InterfaceQuestion("CAN / CAN-FD", "In-vehicle network", ["firmware", "hardware", "operating-system"]),
        InterfaceQuestion("LIN", "Low-speed network", ["firmware", "hardware"]),
        InterfaceQuestion("FlexRay", "High-speed deterministic network", ["firmware", "hardware"]),
        InterfaceQuestion("Automotive Ethernet", "100BASE-T1/1000BASE-T1", ["firmware", "hardware"]),
    ],
    "debug": [
        InterfaceQuestion("JTAG/SWD", "Hardware debug interface", ["hardware", "firmware"]),
        InterfaceQuestion("UART/Serial Console", "Debug console", ["firmware", "operating-system"]),
        InterfaceQuestion("USB Debug", "USB debugging", ["firmware", "operating-system"]),
    ],
    "update": [
        InterfaceQuestion("OTA Update Channel", "Over-the-air updates", ["firmware", "operating-system", "library"]),
        InterfaceQuestion("Workshop Update", "Wired update mechanism", ["firmware"]),
        InterfaceQuestion("Bootloader Update", "Secure boot update", ["firmware"]),
    ],
    "diagnostic": [
        InterfaceQuestion("UDS (ISO 14229)", "Unified Diagnostic Services", ["firmware", "operating-system"]),
        InterfaceQuestion("OBD-II", "On-board diagnostics", ["firmware"]),
        InterfaceQuestion("XCP/CCP", "Calibration protocols", ["firmware"]),
    ],
}


class TriageChecklistGenerator:
    """Generate dynamic triage checklists based on SBOM and vulnerabilities"""

    def __init__(self, results: Dict):
        self.results = results
        self.components = results.get('scanned_components', [])
        self.vulnerabilities = results.get('vulnerabilities', [])

    def get_unique_component_names(self) -> List[str]:
        """Get unique component names from SBOM"""
        names = set()
        for comp in self.components:
            name = comp.get('name', '').lower()
            if name:
                names.add(name)
        return list(names)

    def get_component_types(self) -> List[str]:
        """Get unique component types from SBOM"""
        types = set()
        for comp in self.components:
            comp_type = comp.get('type', 'library').lower()
            types.add(comp_type)
        return list(types)

    def get_affected_cves_for_component(self, component_name: str) -> List[str]:
        """Get list of CVEs affecting a specific component"""
        cves = []
        for vuln in self.vulnerabilities:
            comp = vuln.get('component', {})
            if comp.get('name', '').lower() == component_name.lower():
                cves.append(vuln.get('id', ''))
        return cves

    def generate_config_checklist(self) -> List[Dict]:
        """Generate configuration checklist based on actual components"""
        checklist = []
        component_names = self.get_unique_component_names()

        for comp_name in component_names:
            # Find matching config database
            config_key = self._find_config_key(comp_name)
            config_questions = COMPONENT_CONFIG_DB.get(config_key, COMPONENT_CONFIG_DB["_default"])

            # Get CVEs for this component
            component_cves = self.get_affected_cves_for_component(comp_name)

            # Filter questions to those relevant to found CVEs (or include all if no CVE match)
            relevant_questions = []
            for q in config_questions:
                # Include if question affects found CVEs, or if no specific CVEs listed
                if not q.affects_cves or any(cve in component_cves for cve in q.affects_cves):
                    relevant_questions.append({
                        'component': comp_name,
                        'config_option': q.config_option,
                        'description': q.description,
                        'affects_cves': [c for c in q.affects_cves if c in component_cves] or ['General security'],
                        'question_type': q.question_type,
                    })

            if relevant_questions:
                checklist.extend(relevant_questions)

        return checklist

    def generate_interface_checklist(self) -> List[Dict]:
        """Generate interface checklist based on component types"""
        checklist = []
        component_types = self.get_component_types()

        # Determine which interface categories are relevant
        all_interfaces = []

        for category, interfaces in INTERFACE_DB.items():
            for iface in interfaces:
                # Check if any component type matches
                if any(ct in iface.relevant_for for ct in component_types):
                    all_interfaces.append({
                        'category': category,
                        'interface': iface.interface,
                        'description': iface.description,
                    })

        # Deduplicate
        seen = set()
        for iface in all_interfaces:
            key = iface['interface']
            if key not in seen:
                seen.add(key)
                checklist.append(iface)

        return checklist

    def generate_component_summary(self) -> List[Dict]:
        """Generate summary of components with vulnerability counts"""
        summary = []
        component_names = self.get_unique_component_names()

        for comp_name in component_names:
            cves = self.get_affected_cves_for_component(comp_name)
            comp_info = next((c for c in self.components if c.get('name', '').lower() == comp_name.lower()), {})

            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for vuln in self.vulnerabilities:
                if vuln.get('component', {}).get('name', '').lower() == comp_name.lower():
                    sev = vuln.get('severity', 'Unknown')
                    if sev in severity_counts:
                        severity_counts[sev] += 1

            summary.append({
                'name': comp_name,
                'version': comp_info.get('version', 'Unknown'),
                'type': comp_info.get('type', 'library'),
                'total_cves': len(cves),
                'severity_counts': severity_counts,
                'cve_ids': cves[:10],  # Limit to first 10
            })

        # Sort by total CVEs descending
        summary.sort(key=lambda x: x['total_cves'], reverse=True)
        return summary

    def _find_config_key(self, component_name: str) -> str:
        """Find the best matching config database key for a component"""
        name_lower = component_name.lower()

        # Direct match
        if name_lower in COMPONENT_CONFIG_DB:
            return name_lower

        # Partial match
        for key in COMPONENT_CONFIG_DB.keys():
            if key in name_lower or name_lower in key:
                return key

        # Check for common variations
        variations = {
            'mbed': 'mbedtls',
            'arm-mbed': 'mbedtls',
            'ssl': 'openssl',
            'tls': 'openssl',
            'wolf': 'wolfssl',
            'rtos': 'freertos',
            'safe': 'safertos',
            'shib': 'shibboleth-sp',
        }

        for pattern, key in variations.items():
            if pattern in name_lower:
                return key

        return '_default'

    def generate_full_checklist(self) -> Dict:
        """Generate complete triage checklist data structure"""
        return {
            'component_summary': self.generate_component_summary(),
            'config_checklist': self.generate_config_checklist(),
            'interface_checklist': self.generate_interface_checklist(),
            'total_components': len(self.get_unique_component_names()),
            'total_vulnerabilities': len(self.vulnerabilities),
            'component_types': self.get_component_types(),
        }


def test_checklist_generator():
    """Test the checklist generator with sample data"""
    test_results = {
        'scanned_components': [
            {'name': 'mbedtls', 'version': '2.28.1', 'type': 'library'},
            {'name': 'shibboleth-sp', 'version': '3.4.1', 'type': 'library'},
            {'name': 'safertos', 'version': '5.11', 'type': 'operating-system'},
            {'name': 'stm32f745zet6', 'version': '1.0', 'type': 'hardware'},
        ],
        'vulnerabilities': [
            {'id': 'CVE-2022-35409', 'severity': 'CRITICAL', 'component': {'name': 'mbedtls'}},
            {'id': 'CVE-2022-46393', 'severity': 'CRITICAL', 'component': {'name': 'mbedtls'}},
            {'id': 'CVE-2025-9943', 'severity': 'CRITICAL', 'component': {'name': 'shibboleth-sp'}},
        ]
    }

    generator = TriageChecklistGenerator(test_results)
    checklist = generator.generate_full_checklist()

    print("=== Component Summary ===")
    for comp in checklist['component_summary']:
        print(f"  {comp['name']} {comp['version']}: {comp['total_cves']} CVEs")

    print("\n=== Config Checklist ===")
    for item in checklist['config_checklist'][:5]:
        print(f"  [{item['component']}] {item['config_option']}")
        print(f"    Affects: {item['affects_cves']}")

    print("\n=== Interface Checklist ===")
    for item in checklist['interface_checklist'][:5]:
        print(f"  [{item['category']}] {item['interface']}")


if __name__ == "__main__":
    test_checklist_generator()
