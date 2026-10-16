# Site configuration for example.com
# Test fixture for stop-bots project

server {
    # BEGIN stop-bots (DO NOT EDIT)
    set $stop_bots_block 0;
    if ($http_user_agent ~* "AgentReadinessScanner|AIScan|ArgusScanner|AtomicEdge|BitSightBot|BotDetectorScanner|BrokenLinksBot|cam-scanner|CareerPageBot|CloudAnchor|CMS-Checker|CMS-Detector|CMS-Scanner|Cortex-Xpanse|CT-WP-Scanner|CyberConvoyScout|DomainScores|ExchangeScanner|ExposureScanner|ExposureWatch|FastSourceScanner|feroxbuster|fingerprint-scan|FlowIQ|foda-scanner|ForestEngine|ForestScanner|SQLiScan|FreePBX-Scanner|gitscan|GlobRadarBot|Googlebot\/|Googlebot|GoScanner|HaloSecurity|HelloScan|HighPerfScanner|CompanyPage-Scraper|Infrawatch|internal-scan|HTTP Banner Detection|ipscan|jscrawler|Keydrop|l9explore|l9tcpid|LaravelDetector|LeadHausBot|leak.info|LohiSoftBot|ModatScanner|security research scanner|nextjs-scanner|NextJSDetector|nextscan|NoctraRecon|Nxploited|osint-scanner|pathscan|proximity-sweep|PublicWWWBot|Qwantbot|rawgrab|RecordedFuture|research-scan|RootEvidence|RTSP-Scanner|ScalinthBot|ScanProxy|user agents strings|SecurityAudit|SecurityResearch|SecurityScanner|SEOJuice|SERankingBacklinksBot|Silovik|SleepBot|SmarterMail-Scanner|SofyaBot|tchelebi|TechSpyBot|tttx.net|Umai-Scanner|visionheight|vitesweep|VPN-Scanner|VULN-Audit|vuln_scanner|WanScanner|wkscan|WP-Safe-Scanner|iisec.ac.jp|zern-scanner|zmap-proxy-probe") {
        set $stop_bots_block 1;
    }
    if ($uri ~* "^(/blog/|/robots\.txt$)") {
        set $stop_bots_block 0;
    }
    if ($stop_bots_trusted) {
        set $stop_bots_block 0;
    }
    if ($stop_bots_block) {
        return 410;
    }
    limit_req zone=stop_bots_untrusted burst=11 nodelay;
    limit_req_status 429;
    location = /robots.txt {
        alias /etc/stop-bots/nginx/robots.txt;
        default_type text/plain;
    }
    # END stop-bots

    listen       80;
    listen       [::]:80;
    server_name  example.com www.example.com;

    access_log  /var/log/nginx/example.com.access.log;
    error_log   /var/log/nginx/example.com.error.log;

    root        /var/www/example.com/html;
    index       index.html;

    # Bot protection settings
    # These would be managed by stop-bots
    
    location / {
        try_files $uri $uri/ =404;
    }

    location /wp-admin/ {
        # Additional protection for admin area
        allow 192.168.1.0/24;
        deny all;
    }

    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
