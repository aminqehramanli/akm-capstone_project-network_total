# akm-capstone_project-network_total

This web-based tool is designed to analyze PCAP files using Suricata and Zeek, two powerful network analysis tools. It provides a user-friendly front-end interface where users can upload PCAP files directly through the browser. Once uploaded, the system analyzes the traffic for threats and logs, and presents the results in a clear, searchable format. 

#howdoesitwork

This web-based tool is designed to analyze PCAP files using Suricata and Zeek, two powerful network analysis tools. It provides a user-friendly front-end interface where users can upload PCAP files directly through the browser. Once uploaded, the system analyzes the traffic for threats and logs, and presents results in a clear, searchable format. 

#howdoesitwork

1. Parses Suricata alerts (from eve.json). 
2. Zips and organizes Zeek logs for download.
3. Stores metadata and hash information in a PostgreSQL database.
4. Offers a search box to re-analyze or check previous files using MD5 or SHA256 hashes.
5. If a file has already been analyzed, it skips redundant processing and loads the previous results saving time and resources.
