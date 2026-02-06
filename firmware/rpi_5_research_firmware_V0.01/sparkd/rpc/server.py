"""
SPARK RPC Server

Unix socket server for meshctl communication.

Protocol:
- JSON-RPC 2.0 over Unix domain socket
- One request/response per connection
- Authentication via Unix permissions

Security:
- Socket only accessible to owner (0600)
- No network exposure
- Simple request/response model
"""

import json
import os
import socket
import stat
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from dataclasses import dataclass


# Default socket path
DEFAULT_SOCKET_PATH = Path("/run/spark/sparkd.sock")

# Maximum request size (64KB)
MAX_REQUEST_SIZE = 65536

# Socket timeout (seconds)
SOCKET_TIMEOUT = 30


class RPCError(Exception):
    """RPC error with code and message."""
    
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
    
    def to_dict(self) -> dict:
        result = {"code": self.code, "message": self.message}
        if self.data is not None:
            result["data"] = self.data
        return result


# Standard JSON-RPC error codes
class RPCErrorCode:
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603


# Handler type
RPCHandler = Callable[[dict], Any]


class RPCServer:
    """
    JSON-RPC server over Unix socket.
    
    Usage:
        server = RPCServer()
        
        # Register handlers
        server.register("status", handle_status)
        server.register("peers", handle_peers)
        
        # Start server
        server.start()
        
        # Stop server
        server.stop()
    """
    
    def __init__(
        self,
        socket_path: Optional[Path] = None,
    ):
        """
        Initialize RPC server.
        
        Args:
            socket_path: Path for Unix socket
        """
        self._socket_path = socket_path or DEFAULT_SOCKET_PATH
        self._handlers: Dict[str, RPCHandler] = {}
        self._socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
    
    def register(self, method: str, handler: RPCHandler) -> None:
        """
        Register an RPC method handler.
        
        Args:
            method: Method name
            handler: Handler function (receives params dict, returns result)
        """
        self._handlers[method] = handler
    
    def start(self) -> None:
        """Start the RPC server."""
        if self._running:
            return
        
        # Ensure directory exists
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Remove existing socket
        if self._socket_path.exists():
            self._socket_path.unlink()
        
        # Create socket
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(str(self._socket_path))
        
        # Set permissions (owner only)
        os.chmod(self._socket_path, stat.S_IRUSR | stat.S_IWUSR)
        
        # Listen
        self._socket.listen(5)
        self._socket.settimeout(1.0)  # For clean shutdown
        
        # Start server thread
        self._running = True
        self._thread = threading.Thread(
            target=self._serve_loop,
            daemon=True,
            name="rpc-server",
        )
        self._thread.start()
    
    def stop(self) -> None:
        """Stop the RPC server."""
        self._running = False
        
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        
        if self._socket:
            self._socket.close()
            self._socket = None
        
        # Clean up socket file
        if self._socket_path.exists():
            try:
                self._socket_path.unlink()
            except Exception:
                pass
    
    def _serve_loop(self) -> None:
        """Main server loop."""
        while self._running:
            try:
                conn, _ = self._socket.accept()
                conn.settimeout(SOCKET_TIMEOUT)
                
                # Handle in thread pool (simple approach: inline)
                try:
                    self._handle_connection(conn)
                finally:
                    conn.close()
                    
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    continue
    
    def _handle_connection(self, conn: socket.socket) -> None:
        """Handle a single client connection."""
        try:
            # Read request
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_REQUEST_SIZE:
                    raise RPCError(RPCErrorCode.INVALID_REQUEST, "Request too large")
                # Simple protocol: one JSON object per connection
                try:
                    json.loads(data)
                    break  # Complete JSON received
                except json.JSONDecodeError:
                    continue  # Need more data
            
            if not data:
                return
            
            # Process request
            response = self._process_request(data)
            
            # Send response
            conn.sendall(json.dumps(response).encode() + b"\n")
            
        except Exception as e:
            # Send error response
            error_response = {
                "jsonrpc": "2.0",
                "error": {"code": RPCErrorCode.INTERNAL_ERROR, "message": str(e)},
                "id": None,
            }
            try:
                conn.sendall(json.dumps(error_response).encode() + b"\n")
            except Exception:
                pass
    
    def _process_request(self, data: bytes) -> dict:
        """Process a JSON-RPC request."""
        request_id = None
        
        try:
            # Parse JSON
            try:
                request = json.loads(data)
            except json.JSONDecodeError as e:
                raise RPCError(RPCErrorCode.PARSE_ERROR, f"Parse error: {e}")
            
            # Validate request
            if not isinstance(request, dict):
                raise RPCError(RPCErrorCode.INVALID_REQUEST, "Request must be object")
            
            request_id = request.get("id")
            
            if request.get("jsonrpc") != "2.0":
                raise RPCError(RPCErrorCode.INVALID_REQUEST, "Invalid JSON-RPC version")
            
            method = request.get("method")
            if not isinstance(method, str):
                raise RPCError(RPCErrorCode.INVALID_REQUEST, "Method must be string")
            
            params = request.get("params", {})
            if not isinstance(params, (dict, list)):
                raise RPCError(RPCErrorCode.INVALID_PARAMS, "Params must be object or array")
            
            # Find handler
            handler = self._handlers.get(method)
            if not handler:
                raise RPCError(RPCErrorCode.METHOD_NOT_FOUND, f"Method not found: {method}")
            
            # Call handler
            if isinstance(params, list):
                params = {"_args": params}
            
            result = handler(params)
            
            # Build response
            return {
                "jsonrpc": "2.0",
                "result": result,
                "id": request_id,
            }
            
        except RPCError as e:
            return {
                "jsonrpc": "2.0",
                "error": e.to_dict(),
                "id": request_id,
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "error": {"code": RPCErrorCode.INTERNAL_ERROR, "message": str(e)},
                "id": request_id,
            }
    
    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running


class RPCClient:
    """
    Simple RPC client for testing and meshctl.
    
    Usage:
        client = RPCClient()
        result = client.call("status", {})
        print(result)
    """
    
    def __init__(self, socket_path: Optional[Path] = None):
        """Initialize client."""
        self._socket_path = socket_path or DEFAULT_SOCKET_PATH
    
    def call(self, method: str, params: dict = None) -> Any:
        """
        Call an RPC method.
        
        Args:
            method: Method name
            params: Method parameters
            
        Returns:
            Method result
            
        Raises:
            RPCError: If call fails
        """
        params = params or {}
        
        # Build request
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }
        
        # Connect and send
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        
        try:
            sock.connect(str(self._socket_path))
            sock.sendall(json.dumps(request).encode())
            sock.shutdown(socket.SHUT_WR)
            
            # Read response
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            
            # Parse response
            response = json.loads(data)
            
            if "error" in response:
                error = response["error"]
                raise RPCError(
                    error.get("code", -1),
                    error.get("message", "Unknown error"),
                    error.get("data"),
                )
            
            return response.get("result")
            
        finally:
            sock.close()
