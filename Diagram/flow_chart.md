# System Flow Chart

```mermaid
flowchart TD
    Start([Start]) --> UserInput[User Enters Target URL]
    UserInput --> SelectScan[Select Scan Type]
    
    SelectScan -->|Vulnerability Scan| ScanVuln[vulnerability_scan()]
    SelectScan -->|Port Scan| ScanPort[port_scan()]
    SelectScan -->|Directory Fuzzing| ScanDir[directory_fuzz()]
    SelectScan -->|Tech Detect| ScanTech[technology_detect()]
    SelectScan -->|DNS Recon| ScanDNS[dns_reconnaissance()]
    SelectScan -->|Scan All| ScanAll[Run All Scanners]

    subgraph Backend_Processing [Backend Processing]
        ScanVuln --> Checks{checks: XSS, SQLi, etc.}
        Checks --> ShodanCheck[Shodan CVE Check]
        
        ScanPort --> NmapCheck[Socket Connect / Nmap]
        ScanPort --> ShodanPort[Shodan Host Info]
        
        ScanDir --> FFUF[FFUF / Wordlist Check]
        
        ScanTech --> Signatures[Signature Matching]
        ScanTech --> WhatCMS[WhatCMS API]
        
        ScanDNS --> DoH[DNS Queries (DoH)]
        ScanDNS --> GeoIP[IP Geolocation]
    end

    ShodanCheck --> AggResults[Aggregate Results]
    NmapCheck & ShodanPort --> AggResults
    FFUF --> AggResults
    Signatures & WhatCMS --> AggResults
    DoH & GeoIP --> AggResults

    AggResults --> ReturnJSON[Return JSON Response]
    
    ReturnJSON --> Frontend[Frontend Updates UI]
    Frontend --> RenderTable[Render Results Table/Charts]
    Frontend --> ShowToast[Show Toast Notification]

    RenderTable --> UserAction{User Action}
    UserAction -->|Generate PDF| GenPDF[Call /api/generate-pdf]
    GenPDF --> PDFGen[PDF Generator]
    PDFGen --> Download[Download Report]
    
    UserAction -->|New Scan| Start
```
