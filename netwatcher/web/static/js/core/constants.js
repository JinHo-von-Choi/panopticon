/**
 * NetWatcher Dashboard Constants
 */

export const DEVICE_TYPE_MAP = {
    pc:      { label: "PC",      color: "#3498db", bg: "rgba(52,152,219,0.12)"  },
    mobile:  { label: "Mobile",  color: "#2ed573", bg: "rgba(46,213,115,0.12)"  },
    printer: { label: "Printer", color: "#ffa502", bg: "rgba(255,165,2,0.12)"   },
    router:  { label: "Router",  color: "#a29bfe", bg: "rgba(162,155,254,0.12)" },
    nas:     { label: "NAS",     color: "#00cec9", bg: "rgba(0,206,201,0.12)"   },
    server:  { label: "Server",  color: "#ff4757", bg: "rgba(255,71,87,0.12)"   },
    iot:     { label: "IoT",     color: "#ffc048", bg: "rgba(255,192,72,0.12)"  },
    unknown: { label: "?",       color: "#8b8fa3", bg: "rgba(139,143,163,0.12)" },
};

export const PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB",
    514: "Syslog", 548: "AFP", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1883: "MQTT", 1900: "UPnP", 3000: "Gitea/Node", 3306: "MySQL", 3389: "RDP",
    5000: "Synology", 5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "Dev", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9000: "Portainer", 9090: "Prometheus", 9100: "Printer", 32400: "Plex"
};
