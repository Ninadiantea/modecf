# VLESS+Trojan Cloudflare Worker

A high-performance Cloudflare Worker script that supports VLESS and Trojan protocols over WebSocket with bidirectional communication and proxy routing capabilities.

## Features

- **Multiple Protocol Support**: VLESS and Trojan protocols
- **WebSocket Transport**: Secure WebSocket transport with TLS
- **Bidirectional Communication**: Full two-way communication support
- **Proxy Routing**: Route traffic through specified proxies
- **DNS Proxy**: Built-in DNS over UDP support
- **Multiple User Authentication**: Support for multiple users with UUID authentication
- **Customizable Configuration**: Easily configurable settings
- **Error Handling**: Robust error handling and logging

## Setup Instructions

### Prerequisites

1. A Cloudflare account
2. A domain name connected to Cloudflare
3. Wrangler CLI tool installed (`npm install -g wrangler`)

### Deployment Steps

1. **Clone or download the script files**

   Save the `vless-trojan-worker.js` file to your local machine.

2. **Configure the script**

   Edit the `CONFIG` section in the `vless-trojan-worker.js` file:

   ```javascript
   const CONFIG = {
     // Basic settings
     serviceName: "vless-ws", // Worker name
     rootDomain: "yourdomain.com", // Your domain
     
     // Security settings
     users: [
       { id: "your-uuid-here", name: "default" }, // Generate UUID at https://www.uuidgenerator.net/
       // Add more users as needed
     ],
     
     // Network settings
     ports: [443, 80], // Supported ports
     dnsServer: "8.8.8.8", // DNS server address
     dnsPort: 53, // DNS server port
     
     // Proxy settings
     proxyIPs: [], // Optional: Add specific proxy IPs if needed
     
     // Advanced settings
     enableDNSProxy: true, // Enable DNS proxy
     enableFallback: true, // Enable fallback to direct connection if proxy fails
     logLevel: "info", // Log level: debug, info, warn, error
   };
   ```

   - Replace `"yourdomain.com"` with your actual domain
   - Generate a UUID at https://www.uuidgenerator.net/ and replace `"your-uuid-here"`
   - Add any proxy IPs to the `proxyIPs` array if needed

3. **Create a wrangler.toml file**

   ```toml
   name = "vless-ws"
   main = "vless-trojan-worker.js"
   compatibility_date = "2023-12-01"
   
   [triggers]
   crons = []
   
   [[routes]]
   pattern = "vless-ws.yourdomain.com"
   custom_domain = true
   
   [vars]
   
   [[rules]]
   type = "ESModule"
   globs = ["**/*.js"]
   
   [rules.headers]
   Content-Type = "application/javascript"
   
   [placement]
   mode = "smart"
   ```

   Replace `"vless-ws.yourdomain.com"` with your actual subdomain.

4. **Login to Cloudflare with Wrangler**

   ```bash
   wrangler login
   ```

5. **Deploy the worker**

   ```bash
   wrangler deploy
   ```

6. **Set up DNS record**

   Create an A record in your Cloudflare DNS settings:
   - Type: A
   - Name: vless-ws (or your chosen subdomain)
   - Content: 1.2.3.4 (any IP, as Cloudflare will proxy it)
   - Proxy status: Proxied (orange cloud)

## Client Configuration

### VLESS Client Configuration

For v2ray, Xray, or other VLESS-compatible clients:

```json
{
  "inbounds": [...],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "vless-ws.yourdomain.com",
            "port": 443,
            "users": [
              {
                "id": "your-uuid-here",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "serverName": "vless-ws.yourdomain.com"
        },
        "wsSettings": {
          "path": "/your-path"
        }
      }
    }
  ]
}
```

Replace:
- `vless-ws.yourdomain.com` with your actual domain
- `your-uuid-here` with the UUID you configured in the worker
- `your-path` with any path you want to use (this will be the proxy target path)

### Trojan Client Configuration

For Trojan-compatible clients:

```json
{
  "run_type": "client",
  "local_addr": "127.0.0.1",
  "local_port": 1080,
  "remote_addr": "vless-ws.yourdomain.com",
  "remote_port": 443,
  "password": ["your-uuid-here"],
  "websocket": {
    "enabled": true,
    "path": "/your-path",
    "hostname": "vless-ws.yourdomain.com"
  },
  "ssl": {
    "verify": true,
    "verify_hostname": true,
    "sni": "vless-ws.yourdomain.com"
  }
}
```

## Proxy Routing

The worker supports proxy routing through the path parameter. When connecting, use a path in the format:

```
/proxy-ip:proxy-port
```

For example:
- `/1.2.3.4:443` - Route through the proxy at 1.2.3.4:443
- `/proxy.example.com:8443` - Route through the proxy at proxy.example.com:8443

If no proxy is specified in the path, the worker will attempt a direct connection first, and if that fails, it will use one of the configured proxy IPs (if any are defined).

## Advanced Usage

### Multiple Users

You can add multiple users by adding more entries to the `users` array:

```javascript
users: [
  { id: "uuid1-here", name: "user1" },
  { id: "uuid2-here", name: "user2" },
  { id: "uuid3-here", name: "admin" }
]
```

### Custom DNS Server

You can change the DNS server by modifying the `dnsServer` and `dnsPort` settings:

```javascript
dnsServer: "1.1.1.1", // Cloudflare DNS
dnsPort: 53
```

### Logging Levels

Adjust the logging verbosity by changing the `logLevel`:

```javascript
logLevel: "debug" // Options: debug, info, warn, error
```

## Troubleshooting

### Connection Issues

1. **Check your Cloudflare settings**:
   - Ensure SSL/TLS encryption mode is set to "Full" or "Full (strict)"
   - Verify that WebSockets are enabled in the Network tab

2. **Verify your UUID**:
   - Make sure the UUID in your client matches the one in the worker configuration

3. **Check the worker logs**:
   - Go to the Cloudflare dashboard > Workers > Your Worker > Logs
   - Look for any error messages

### Performance Optimization

1. **Use Cloudflare Argo**:
   - Enable Argo Smart Routing for better performance

2. **Adjust WebSocket settings**:
   - Some clients allow adjusting WebSocket parameters like keep-alive intervals

## Security Considerations

1. **Rotate UUIDs regularly**:
   - Change your UUIDs periodically for better security

2. **Use strong UUIDs**:
   - Always use randomly generated UUIDs, never predictable values

3. **Limit access**:
   - Consider using Cloudflare Access policies to restrict who can connect

## License

This project is released under the MIT License.

## Disclaimer

This tool is provided for educational and research purposes only. Users are responsible for ensuring their use complies with applicable laws and regulations.