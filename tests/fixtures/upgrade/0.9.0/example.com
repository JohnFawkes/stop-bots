# Site configuration for example.com
# Test fixture for stop-bots project

server {
    # BEGIN stop-bots (DO NOT EDIT)
    set $stop_bots_block 0;
    if ($http_user_agent ~* "adaptive-bot|ads-txt-crawler|adscan|AdsNexusBot|AdsTxtBot|AgentReadinessScanner|AIScan|ApcosysBot|app-ads-crawler|ArgusScanner|AssetCheck|AtomicEdge|bearblog-outreach|BesaCrawler|bgp-scan|BitSightBot|BotDetectorScanner|br-crawler|BrokenLinksBot|cam-scanner|CareerPageBot|CiscoScanner|CiscoSSLVPNScanner|CloudAnchor|CMS-Checker|CMS-Detector|cms-port-check|CMS-Scanner|CohereBot|Cortex-Xpanse|CSSCheck|CT-WP-Scanner|CyberConvoyScout|darkalgo-research|DataFoundationResearch|DomainScores|DomainSignalAudit|eManagerBot|EnvScanner|ExchangeScanner|Exposure-Scanner|ExposureScanner|ExposureWatch|FastScan|FastSourceScanner|feroxbuster|fingerprint-scan|FlowIQ|foda-scanner|ForestEngine|ForestScanner|form-pilot|SQLiScan|FossickBot|FreePBX-Scanner|gbrmss|getdomaindata|gitscan|PAN GlobalProtect|GlobRadarBot|Web Pentest|Googlebot\/|Googlebot|GoScanner|GulperBot|HaloSecurity|Hello World|Hello, World|HelloScan|HighPerfScanner|http-vs-https|HTTPHeadersCheck|HuaweiCrawler|HUNT-Bot|CompanyPage-Scraper|Infrawatch|internal-scan|ip_scanner|HTTP Banner Detection|ipscan|IronFountain|jscrawler|Keydrop|DNSRenewal-Study|l9explore|l9tcpid|LaravelDetector|LeadHausBot|leak.info|Linux Gnu|LohiSoftBot|MeasureboardResearch|MentoDomainAudit|metaphor-data-pipeline|MetodaSearchBot|WinRM Client|Milesight|MistralBot|ModatScanner|msh-pdfmin|netapi.com|security research scanner|NetsurferBot|NewsletterFormResearch|nextjs-scanner|NextJSDetector|nextscan|nginx-loadcheck|NoctraRecon|GNSSInternetRadio|NuFoundersLeadResearch|Nxploited|obsrvr.net|opr-crawler|osentix|osint-scanner|pathscan|peers-researcher-index|PisarBot|PlytikBot|PragmaticSecurity|proximity-sweep|proxy_checker|public-homepage-check|PublicWWWBot|ncsrv|QlyzeBot|Qwantbot|r00ts3c|RankPulseBot|rawgrab|RecordedFuture|research-scan|RootCrawl|RootEvidence|RTSP-Scanner|SaaSBrowserBot|ScalinthBot|ScanProxy|user agents strings|SecurityAudit|SecurityResearch|SecurityScanner|SEOJuice|SERankingBacklinksBot|Silovik|SleepBot|smallweb-check|SmarterMail-Scanner") {
        set $stop_bots_block 1;
    }
    if ($http_user_agent ~* "Software Security Research|SofyaBot|SonarPrime|SPARK COMMIT|sponsorsearch-validation|StumbleBot|tchelebi|TechSpyBot|TokenadeResearch|tttx.net|txtbot.net|ucp-crawler|Umai-Scanner|understory|visionheight|vitesweep|VPN-Scanner|VULN-Audit|vuln_scanner|WanScanner|Web Downloader|WebAnalyzer|WebatlaBot|WebReviveBot|website-analysis|what-vpn|wkscan|WordPressPostChecker|WP-Safe-Scanner|yacycrawler|iisec.ac.jp|zern-scanner|zmap-proxy-probe") {
        set $stop_bots_block 1;
    }
    set $stop_bots_path $uri;
    if ($request_uri ~ "^(/[^?%#\\\]*)(\?.*)?$") {
        set $stop_bots_path $1;
    }
    if ($stop_bots_path ~ "//|/\.\.?(/|$)") {
        set $stop_bots_path $uri;
    }
    if ($stop_bots_path ~* "^(/blog/|/robots\.txt$)") {
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
