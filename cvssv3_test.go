package cvssv3

import (
	"fmt"
	"testing"
)

func TestBaseScore(t *testing.T) {
	d := map[string]float64 {
		// phpMyAdmin Reflected Cross-site Scripting Vulnerability (CVE-2013-1937)
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		// MySQL Stored SQL Injection (CVE-2013-0375)
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
		// SSLv3 POODLE Vulnerability (CVE-2014-3566)
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,
		// VMware Guest to Host Escape Vulnerability (CVE-2012-1516)
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
		// Apache Tomcat XML Parser Vulnerability (CVE-2009-0783)
		"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L": 4.2,
		// Cisco IOS Arbitrary Command Execution Vulnerability (CVE-2012-0384)
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
		// Apple iWork Denial of Service Vulnerability (CVE-2015-1098)
		// Adobe Acrobat Buffer Overflow Vulnerability (CVE-2009-0658)
		"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H": 7.8,
		// OpenSSL Heartbleed Vulnerability (CVE-2014-0160)
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
		// GNU Bourne-Again Shell (Bash) 'Shellshock' Vulnerability (CVE-2014-6271)
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		// DNS Kaminsky Bug (CVE-2008-1447)
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N": 6.8,
		// Sophos Login Screen Bypass Vulnerability (CVE-2014-2005)
		"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 6.8,
		// Joomla Directory Traversal Vulnerability (CVE-2010-0467)
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N": 5.8,
		// Cisco Access Control Bypass Vulnerability (CVE-2012-1342)
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N": 5.8,
		// Juniper Proxy ARP Denial of Service Vulnerability (CVE-2013-6014)
		"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H": 9.3,
		// DokuWiki Reflected Cross-site Scripting Attack (CVE-2014-9253)
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 5.4,
		// Microsoft Windows Bluetooth Remote Code Execution Vulnerability (CVE-2011-1265)
		"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.8,
		// Apple iOS Security Control Bypass Vulnerability (CVE-2014-2019)
		"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N": 4.6,
		// SearchBlox Cross-Site Request Forgery Vulnerability (CVE-2015-0970)
		// Google Chrome PDFium JPEG 2000 Remote Code Execution Vulnerability (CVE-2016-1645)
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H": 8.8,
		// SSL/TLS MITM Vulnerability (CVE-2014-0224)
		// SAMR/LSAD Privilege Escalation via Protocol Downgrade Vulnerability (“Badlock”) (CVE-2016-0128 and CVE-2016-2118)
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N": 7.4,
		// Google Chrome Sandbox Bypass vulnerability (CVE-2012-5376)
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H": 9.6,
	}
	for vs,expected := range d {
		m, err := ParseVector(vs)
		if err == nil {
			actual := m.BaseScore()
			fmt.Printf("%s, expected = %4.1f, actual = %4.1f\n", vs, expected, actual)
			if actual != expected {
				t.Errorf("fot %v, want %v.", actual, expected)
			}
		} else {
			t.Errorf("parse error: %s", vs)
		}
	}
}
// End of cvssv3_test.go