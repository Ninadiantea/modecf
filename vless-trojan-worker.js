/**
 * VLESS+Trojan Cloudflare Worker Script
 * Supports WebSocket, bidirectional communication, and proxy routing
 * 
 * Features:
 * - VLESS and Trojan protocol support
 * - WebSocket transport with TLS
 * - Bidirectional communication
 * - Proxy routing capabilities
 * - DNS over UDP support
 * - Multiple user authentication
 * - Customizable configuration
 */

import { connect } from "cloudflare:sockets";

// ======= CONFIGURATION =======
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

// ======= CONSTANTS =======
const APP_DOMAIN = `${CONFIG.serviceName}.${CONFIG.rootDomain}`;
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Max-Age": "86400",
};

// ======= MAIN WORKER =======
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");
      
      // Handle WebSocket connections
      if (upgradeHeader?.toLowerCase() === "websocket") {
        return await handleWebSocketConnection(request, url);
      }
      
      // Handle HTTP requests
      return await handleHttpRequest(request, url);
    } catch (err) {
      return createErrorResponse(err);
    }
  },
};

// ======= HTTP HANDLER =======
async function handleHttpRequest(request, url) {
  // Handle OPTIONS request (CORS preflight)
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: CORS_HEADERS,
    });
  }
  
  // Health check endpoint
  if (url.pathname === "/health") {
    return new Response(JSON.stringify({ status: "ok", timestamp: new Date().toISOString() }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        ...CORS_HEADERS,
      },
    });
  }
  
  // Status endpoint
  if (url.pathname === "/status") {
    return new Response(JSON.stringify({
      status: "running",
      version: "1.0.0",
      protocols: ["vless", "trojan"],
      transport: "websocket",
      timestamp: new Date().toISOString(),
    }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        ...CORS_HEADERS,
      },
    });
  }
  
  // Default response - can be customized to serve a landing page or redirect
  return new Response("Not Found", { status: 404 });
}

// ======= WEBSOCKET HANDLER =======
async function handleWebSocketConnection(request, url) {
  // Extract target from path
  const pathMatch = url.pathname.match(/^\\/(.+)$/);
  let proxyTarget = "";
  
  if (pathMatch) {
    proxyTarget = pathMatch[1];
  }
  
  // Create WebSocket pair
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);
  
  // Accept the WebSocket connection
  server.accept();
  
  // Setup logging
  let addressLog = "";
  let portLog = "";
  const log = (level, info, event) => {
    if (getLogLevelValue(level) >= getLogLevelValue(CONFIG.logLevel)) {
      console.log(`[${level.toUpperCase()}][${addressLog}:${portLog}] ${info}`, event || "");
    }
  };
  
  // Get early data if available
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  
  // Create readable stream from WebSocket
  const readableWebSocketStream = makeReadableWebSocketStream(server, earlyDataHeader, log);
  
  // Remote socket wrapper
  let remoteSocketWrapper = {
    value: null,
  };
  
  // Flag for DNS requests
  let isDNS = false;
  
  // Pipe WebSocket data to handler
  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          // Handle DNS requests
          if (isDNS) {
            return handleUDPOutbound(CONFIG.dnsServer, CONFIG.dnsPort, chunk, server, null, log);
          }
          
          // If remote socket exists, write to it
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }
          
          // Detect protocol and parse header
          const protocol = await detectProtocol(chunk);
          let protocolHeader;
          
          if (protocol === "vless") {
            protocolHeader = parseVLESSHeader(chunk, CONFIG.users);
          } else if (protocol === "trojan") {
            protocolHeader = parseTrojanHeader(chunk, CONFIG.users);
          } else {
            throw new Error(`Unsupported protocol: ${protocol}`);
          }
          
          // Set logging info
          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;
          
          // Check for errors
          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }
          
          // Authentication check
          if (!protocolHeader.authenticated) {
            throw new Error("Authentication failed: Invalid user ID");
          }
          
          // Handle UDP requests
          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53 && CONFIG.enableDNSProxy) {
              isDNS = true;
              log("debug", `Handling DNS request to ${CONFIG.dnsServer}:${CONFIG.dnsPort}`);
              return handleUDPOutbound(
                CONFIG.dnsServer,
                CONFIG.dnsPort,
                chunk,
                server,
                protocolHeader.version,
                log
              );
            } else {
              throw new Error("UDP only supported for DNS (port 53)");
            }
          }
          
          // Handle TCP outbound
          log("info", `Handling TCP connection to ${protocolHeader.addressRemote}:${protocolHeader.portRemote}`);
          handleTCPOutbound(
            remoteSocketWrapper,
            protocolHeader.addressRemote,
            protocolHeader.portRemote,
            protocolHeader.rawClientData,
            server,
            protocolHeader.version,
            log,
            proxyTarget
          );
        },
        close() {
          log("info", "WebSocket stream closed");
        },
        abort(reason) {
          log("error", "WebSocket stream aborted", reason);
        },
      })
    )
    .catch((err) => {
      log("error", "Error in WebSocket stream", err);
    });
  
  // Return WebSocket response
  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

// ======= PROTOCOL HANDLERS =======

/**
 * Create a readable stream from a WebSocket
 */
function makeReadableWebSocketStream(webSocket, earlyDataHeader, log) {
  let readableStreamCancel = false;
  
  return new ReadableStream({
    start(controller) {
      // Handle WebSocket messages
      webSocket.addEventListener("message", (event) => {
        if (readableStreamCancel) return;
        const message = event.data;
        controller.enqueue(message);
      });
      
      // Handle WebSocket close
      webSocket.addEventListener("close", () => {
        safeCloseWebSocket(webSocket);
        if (readableStreamCancel) return;
        controller.close();
      });
      
      // Handle WebSocket errors
      webSocket.addEventListener("error", (err) => {
        log("error", "WebSocket error", err);
        controller.error(err);
      });
      
      // Handle early data if present
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    
    pull(controller) {
      // This is called when the consumer is ready to receive more data
    },
    
    cancel(reason) {
      if (readableStreamCancel) return;
      log("debug", `ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocket);
    },
  });
}

/**
 * Handle TCP outbound connections
 */
async function handleTCPOutbound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  log,
  proxyTarget
) {
  // Function to connect and write data
  async function connectAndWrite(address, port) {
    log("debug", `Connecting to ${address}:${port}`);
    
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    
    remoteSocket.value = tcpSocket;
    log("info", `Connected to ${address}:${port}`);
    
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    
    return tcpSocket;
  }
  
  // Function to retry connection through proxy
  async function retry() {
    let targetAddress = addressRemote;
    let targetPort = portRemote;
    
    // Use proxy target if specified
    if (proxyTarget) {
      const parts = proxyTarget.split(/[:=-]/);
      if (parts.length >= 1) targetAddress = parts[0];
      if (parts.length >= 2) targetPort = parseInt(parts[1]);
      
      log("info", `Retrying through proxy: ${targetAddress}:${targetPort}`);
    } else if (CONFIG.proxyIPs.length > 0) {
      // Use a random proxy from the configured list
      const randomProxy = CONFIG.proxyIPs[Math.floor(Math.random() * CONFIG.proxyIPs.length)];
      const parts = randomProxy.split(":");
      
      if (parts.length >= 1) targetAddress = parts[0];
      if (parts.length >= 2) targetPort = parseInt(parts[1]);
      
      log("info", `Retrying through random proxy: ${targetAddress}:${targetPort}`);
    } else {
      log("warn", "No proxy available for retry");
      return;
    }
    
    try {
      const tcpSocket = await connectAndWrite(targetAddress, targetPort);
      
      tcpSocket.closed
        .catch((error) => {
          log("error", "Proxy connection closed with error", error);
        })
        .finally(() => {
          safeCloseWebSocket(webSocket);
        });
      
      remoteSocketToWebSocket(tcpSocket, webSocket, responseHeader, null, log);
    } catch (error) {
      log("error", `Proxy connection failed: ${error.message}`);
      safeCloseWebSocket(webSocket);
    }
  }
  
  // Try direct connection first
  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWebSocket(tcpSocket, webSocket, responseHeader, CONFIG.enableFallback ? retry : null, log);
  } catch (error) {
    log("warn", `Direct connection failed: ${error.message}`);
    
    if (CONFIG.enableFallback) {
      await retry();
    } else {
      log("error", "Connection failed and fallback is disabled");
      safeCloseWebSocket(webSocket);
    }
  }
}

/**
 * Handle UDP outbound connections (primarily for DNS)
 */
async function handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({
      hostname: targetAddress,
      port: targetPort,
    });
    
    log("debug", `Connected to ${targetAddress}:${targetPort} for UDP`);
    
    const writer = tcpSocket.writable.getWriter();
    await writer.write(udpChunk);
    writer.releaseLock();
    
    await tcpSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            if (protocolHeader) {
              webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
              protocolHeader = null;
            } else {
              webSocket.send(chunk);
            }
          }
        },
        close() {
          log("debug", `UDP connection to ${targetAddress} closed`);
        },
        abort(reason) {
          log("error", `UDP connection to ${targetPort} aborted`, reason);
        },
      })
    );
  } catch (e) {
    log("error", `Error handling UDP outbound: ${e.message}`);
  }
}

/**
 * Pipe data from remote socket to WebSocket
 */
async function remoteSocketToWebSocket(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          hasIncomingData = true;
          
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("WebSocket is not open");
            return;
          }
          
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log("debug", `Remote connection closed (hasIncomingData: ${hasIncomingData})`);
        },
        abort(reason) {
          log("error", `Remote connection aborted`, reason);
        },
      })
    )
    .catch((error) => {
      log("error", `Error in remote socket to WebSocket pipe`, error);
      safeCloseWebSocket(webSocket);
    });
  
  // If no data was received, retry if a retry function is provided
  if (hasIncomingData === false && retry) {
    log("info", `No data received, retrying...`);
    retry();
  }
}

// ======= PROTOCOL PARSERS =======

/**
 * Detect the protocol from the incoming data
 */
async function detectProtocol(buffer) {
  // Check for VLESS protocol signature (version byte is 0)
  const vlessSignature = new Uint8Array(buffer.slice(0, 1));
  if (vlessSignature[0] === 0) {
    return "vless";
  }
  
  // Check for Trojan protocol signature (UUID followed by CRLF)
  const possibleUUID = arrayBufferToHex(buffer.slice(0, 16));
  const crlf = new Uint8Array(buffer.slice(16, 18));
  
  if (possibleUUID.match(/^[0-9a-f]{32}$/i) && crlf[0] === 0x0d && crlf[1] === 0x0a) {
    return "trojan";
  }
  
  // Default to VLESS if can't determine
  return "vless";
}

/**
 * Parse VLESS protocol header
 */
function parseVLESSHeader(buffer, users) {
  try {
    const version = new Uint8Array(buffer.slice(0, 1))[0];
    
    // Extract UUID (16 bytes after version)
    const userID = arrayBufferToHex(buffer.slice(1, 17));
    
    // Authenticate user
    const authenticated = users.some(user => userID === user.id.replace(/-/g, ""));
    
    // Skip additional info length
    const additionalInfoLength = new Uint8Array(buffer.slice(17, 18))[0];
    let pos = 18 + additionalInfoLength;
    
    // Command (TCP/UDP)
    const command = new Uint8Array(buffer.slice(pos, pos + 1))[0];
    const isUDP = command === 2;
    pos += 1;
    
    // Port (2 bytes)
    const portBuffer = buffer.slice(pos, pos + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    pos += 2;
    
    // Address type
    const addressType = new Uint8Array(buffer.slice(pos, pos + 1))[0];
    pos += 1;
    
    let addressLength = 0;
    let addressValue = "";
    
    switch (addressType) {
      case 1: // IPv4
        addressLength = 4;
        addressValue = new Uint8Array(buffer.slice(pos, pos + addressLength)).join(".");
        break;
      case 2: // Domain name
        addressLength = new Uint8Array(buffer.slice(pos, pos + 1))[0];
        pos += 1;
        addressValue = new TextDecoder().decode(buffer.slice(pos, pos + addressLength));
        break;
      case 3: // IPv6
        addressLength = 16;
        const ipv6View = new DataView(buffer.slice(pos, pos + addressLength));
        const ipv6Parts = [];
        for (let i = 0; i < 8; i++) {
          ipv6Parts.push(ipv6View.getUint16(i * 2).toString(16));
        }
        addressValue = ipv6Parts.join(":");
        break;
      default:
        return {
          hasError: true,
          message: `Invalid address type: ${addressType}`,
        };
    }
    
    if (!addressValue) {
      return {
        hasError: true,
        message: `Empty address value (type: ${addressType})`,
      };
    }
    
    // Raw client data starts after the address
    const rawDataIndex = pos + addressLength;
    
    return {
      hasError: false,
      authenticated: authenticated,
      addressRemote: addressValue,
      addressType: addressType,
      portRemote: portRemote,
      rawDataIndex: rawDataIndex,
      rawClientData: buffer.slice(rawDataIndex),
      version: new Uint8Array([version, 0]),
      isUDP: isUDP,
    };
  } catch (error) {
    return {
      hasError: true,
      message: `Error parsing VLESS header: ${error.message}`,
    };
  }
}

/**
 * Parse Trojan protocol header
 */
function parseTrojanHeader(buffer, users) {
  try {
    // Extract UUID (first 16 bytes)
    const userID = arrayBufferToHex(buffer.slice(0, 16));
    
    // Authenticate user
    const authenticated = users.some(user => userID === user.id.replace(/-/g, ""));
    
    // Skip CRLF (2 bytes after UUID)
    let pos = 18;
    
    // Command (TCP/UDP)
    const command = new Uint8Array(buffer.slice(pos, pos + 1))[0];
    const isUDP = command === 0x03; // 0x01 for TCP, 0x03 for UDP
    pos += 1;
    
    // Address type
    const addressType = new Uint8Array(buffer.slice(pos, pos + 1))[0];
    pos += 1;
    
    let addressLength = 0;
    let addressValue = "";
    
    switch (addressType) {
      case 0x01: // IPv4
        addressLength = 4;
        addressValue = new Uint8Array(buffer.slice(pos, pos + addressLength)).join(".");
        break;
      case 0x03: // Domain name
        addressLength = new Uint8Array(buffer.slice(pos, pos + 1))[0];
        pos += 1;
        addressValue = new TextDecoder().decode(buffer.slice(pos, pos + addressLength));
        break;
      case 0x04: // IPv6
        addressLength = 16;
        const ipv6View = new DataView(buffer.slice(pos, pos + addressLength));
        const ipv6Parts = [];
        for (let i = 0; i < 8; i++) {
          ipv6Parts.push(ipv6View.getUint16(i * 2).toString(16));
        }
        addressValue = ipv6Parts.join(":");
        break;
      default:
        return {
          hasError: true,
          message: `Invalid address type: ${addressType}`,
        };
    }
    
    if (!addressValue) {
      return {
        hasError: true,
        message: `Empty address value (type: ${addressType})`,
      };
    }
    
    // Port (2 bytes)
    const portPos = pos + addressLength;
    const portBuffer = buffer.slice(portPos, portPos + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    
    // Raw client data starts after the port (and CRLF)
    const rawDataIndex = portPos + 4; // +2 for port, +2 for CRLF
    
    return {
      hasError: false,
      authenticated: authenticated,
      addressRemote: addressValue,
      addressType: addressType,
      portRemote: portRemote,
      rawDataIndex: rawDataIndex,
      rawClientData: buffer.slice(rawDataIndex),
      version: null,
      isUDP: isUDP,
    };
  } catch (error) {
    return {
      hasError: true,
      message: `Error parsing Trojan header: ${error.message}`,
    };
  }
}

// ======= UTILITY FUNCTIONS =======

/**
 * Safely close a WebSocket
 */
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("Error closing WebSocket", error);
  }
}

/**
 * Convert base64 string to ArrayBuffer
 */
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arrayBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arrayBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

/**
 * Convert ArrayBuffer to hex string
 */
function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Create an error response
 */
function createErrorResponse(error) {
  return new Response(`Error: ${error.message || error.toString()}`, {
    status: 500,
    headers: CORS_HEADERS,
  });
}

/**
 * Get numeric value for log level
 */
function getLogLevelValue(level) {
  const levels = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };
  
  return levels[level.toLowerCase()] || 1;
}