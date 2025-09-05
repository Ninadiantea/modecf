import { connect } from "cloudflare:sockets";

// Configuration - Change these values
const config = {
  // Your domain settings
  domain: "yourdomain.com", // Change to your domain
  serviceName: "vless-ws", // Change to your preferred worker name
  
  // Proxy settings
  proxyIPs: [], // Optional: Add specific proxy IPs if needed
  
  // Security settings
  userID: "your-uuid-here", // Change this to your UUID (generate with: https://www.uuidgenerator.net/)
  
  // Network settings
  ports: [443, 80], // Ports to use
  dnsServer: "8.8.8.8", // DNS server for DNS queries
  dnsPort: 53, // DNS server port
};

// Constants
const APP_DOMAIN = `${config.serviceName}.${config.domain}`;
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Max-Age": "86400",
};

/**
 * Main handler for incoming requests
 */
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");
      
      // Handle WebSocket connections
      if (upgradeHeader === "websocket") {
        // Extract target from path
        const pathMatch = url.pathname.match(/^\\/(.+)$/);
        if (pathMatch) {
          // Set proxy target from path
          const proxyTarget = pathMatch[1];
          return await handleWebSocket(request, proxyTarget);
        }
      }
      
      // Handle HTTP requests (for health checks or API)
      if (url.pathname === "/health") {
        return new Response("OK", { status: 200 });
      }
      
      // Default response for other requests
      return new Response("Not Found", { status: 404 });
    } catch (err) {
      return new Response(`Error: ${err.toString()}`, {
        status: 500,
        headers: CORS_HEADERS,
      });
    }
  },
};

/**
 * Handle WebSocket connections
 * @param {Request} request - The incoming request
 * @param {string} proxyTarget - The target to proxy to
 */
async function handleWebSocket(request, proxyTarget) {
  // Create WebSocket pair
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);
  
  // Accept the WebSocket connection
  server.accept();
  
  // Setup logging
  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
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
            return handleUDPOutbound(config.dnsServer, config.dnsPort, chunk, server, null, log);
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
            protocolHeader = parseVLESSHeader(chunk);
          } else if (protocol === "trojan") {
            protocolHeader = parseTrojanHeader(chunk);
          } else {
            throw new Error("Unsupported protocol");
          }
          
          // Set logging info
          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;
          
          // Check for errors
          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }
          
          // Handle UDP requests
          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
              return handleUDPOutbound(
                config.dnsServer,
                config.dnsPort,
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
          log("WebSocket stream closed");
        },
        abort(reason) {
          log("WebSocket stream aborted", JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("Error in WebSocket stream", err);
    });
  
  // Return WebSocket response
  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

/**
 * Create a readable stream from a WebSocket
 * @param {WebSocket} webSocket - The WebSocket to read from
 * @param {string} earlyDataHeader - Early data header
 * @param {Function} log - Logging function
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
        log("WebSocket error");
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
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocket);
    },
  });
}

/**
 * Handle TCP outbound connections
 * @param {Object} remoteSocket - Remote socket wrapper
 * @param {string} addressRemote - Remote address
 * @param {number} portRemote - Remote port
 * @param {ArrayBuffer} rawClientData - Raw client data
 * @param {WebSocket} webSocket - WebSocket to send responses to
 * @param {ArrayBuffer} responseHeader - Response header
 * @param {Function} log - Logging function
 * @param {string} proxyTarget - Optional proxy target
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
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    
    remoteSocket.value = tcpSocket;
    log(`Connected to ${address}:${port}`);
    
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
    }
    
    const tcpSocket = await connectAndWrite(targetAddress, targetPort);
    
    tcpSocket.closed
      .catch((error) => {
        log("Retry connection closed with error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    
    remoteSocketToWebSocket(tcpSocket, webSocket, responseHeader, null, log);
  }
  
  // Try direct connection first
  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWebSocket(tcpSocket, webSocket, responseHeader, retry, log);
  } catch (error) {
    log(`Direct connection failed: ${error}. Trying proxy...`);
    await retry();
  }
}

/**
 * Handle UDP outbound connections (primarily for DNS)
 * @param {string} targetAddress - Target address
 * @param {number} targetPort - Target port
 * @param {ArrayBuffer} udpChunk - UDP data chunk
 * @param {WebSocket} webSocket - WebSocket to send responses to
 * @param {ArrayBuffer} responseHeader - Response header
 * @param {Function} log - Logging function
 */
async function handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({
      hostname: targetAddress,
      port: targetPort,
    });
    
    log(`Connected to ${targetAddress}:${targetPort} for UDP`);
    
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
          log(`UDP connection to ${targetAddress} closed`);
        },
        abort(reason) {
          log(`UDP connection to ${targetPort} aborted due to ${reason}`);
        },
      })
    );
  } catch (e) {
    log(`Error handling UDP outbound: ${e.message}`);
  }
}

/**
 * Pipe data from remote socket to WebSocket
 * @param {Object} remoteSocket - Remote socket
 * @param {WebSocket} webSocket - WebSocket to send data to
 * @param {ArrayBuffer} responseHeader - Response header
 * @param {Function} retry - Retry function
 * @param {Function} log - Logging function
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
          log(`Remote connection closed (hasIncomingData: ${hasIncomingData})`);
        },
        abort(reason) {
          log(`Remote connection aborted`, reason);
        },
      })
    )
    .catch((error) => {
      log(`Error in remote socket to WebSocket pipe`, error);
      safeCloseWebSocket(webSocket);
    });
  
  // If no data was received, retry if a retry function is provided
  if (hasIncomingData === false && retry) {
    log(`No data received, retrying...`);
    retry();
  }
}

/**
 * Safely close a WebSocket
 * @param {WebSocket} socket - WebSocket to close
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
 * Detect the protocol from the incoming data
 * @param {ArrayBuffer} buffer - Incoming data
 * @returns {string} - Detected protocol
 */
async function detectProtocol(buffer) {
  // Check for VLESS protocol signature
  const vlessSignature = new Uint8Array(buffer.slice(0, 1));
  if (vlessSignature[0] === 0) {
    return "vless";
  }
  
  // Check for Trojan protocol signature (UUID in hex format)
  const trojanSignature = new Uint8Array(buffer.slice(0, 16));
  const possibleUUID = arrayBufferToHex(trojanSignature.buffer);
  if (possibleUUID.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
    return "trojan";
  }
  
  // Default to VLESS
  return "vless";
}

/**
 * Parse VLESS protocol header
 * @param {ArrayBuffer} buffer - Incoming data
 * @returns {Object} - Parsed header
 */
function parseVLESSHeader(buffer) {
  try {
    const version = new Uint8Array(buffer.slice(0, 1))[0];
    
    // Verify UUID (16 bytes after version)
    const uuid = arrayBufferToHex(buffer.slice(1, 17));
    
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
 * @param {ArrayBuffer} buffer - Incoming data
 * @returns {Object} - Parsed header
 */
function parseTrojanHeader(buffer) {
  try {
    // Skip UUID (16 bytes) and CRLF (2 bytes)
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

/**
 * Convert base64 string to ArrayBuffer
 * @param {string} base64Str - Base64 string
 * @returns {Object} - ArrayBuffer or error
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
 * @param {ArrayBuffer} buffer - ArrayBuffer
 * @returns {string} - Hex string
 */
function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}