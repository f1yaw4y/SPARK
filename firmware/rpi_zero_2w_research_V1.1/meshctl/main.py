#!/usr/bin/env python3
"""
meshctl - SPARK Mesh Router CLI

Command-line interface for interacting with the sparkd daemon.

Usage:
    meshctl status      - Show node status
    meshctl peers       - List discovered peers
    meshctl regions     - Show region topology
    meshctl routes      - Display routing table
    meshctl send        - Send a message
    meshctl inbox       - Check inbox
    meshctl read        - Read a message
    meshctl debug       - Show debug information
"""

import sys
import time
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sparkd.rpc.server import RPCClient, RPCError


# Default socket path
DEFAULT_SOCKET = Path("/run/spark/sparkd.sock")


class MeshCtl:
    """meshctl CLI application."""
    
    def __init__(self, socket_path: Path):
        """Initialize CLI with socket path."""
        self.client = RPCClient(socket_path)
    
    def status(self) -> int:
        """Show node status."""
        try:
            result = self.client.call("status")
        except RPCError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Failed to connect to sparkd: {e}", file=sys.stderr)
            return 1
        
        print("SPARK Node Status")
        print("=" * 40)
        print(f"Version:   {result.get('version', 'unknown')}")
        print(f"Node ID:   {result.get('node_id', 'unknown')}")
        print(f"Role:      {result.get('role', 'unknown')}")
        print(f"Peers:     {result.get('peers', 0)}")
        
        region_id = result.get('region_id')
        if region_id:
            print(f"Region:    {region_id[:16]}...")
        else:
            print("Region:    (not assigned)")
        
        radio = result.get('radio')
        if radio:
            print()
            print("Radio:")
            print(f"  State:   {radio.get('state', 'unknown')}")
            print(f"  TX:      {radio.get('packets_sent', 0)} packets")
            print(f"  RX:      {radio.get('packets_received', 0)} packets")
        
        return 0
    
    def peers(self) -> int:
        """List discovered peers."""
        try:
            result = self.client.call("peers")
        except RPCError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Failed to connect to sparkd: {e}", file=sys.stderr)
            return 1
        
        peers = result.get('peers', [])
        
        if not peers:
            print("No peers discovered")
            return 0
        
        print(f"Discovered Peers ({len(peers)})")
        print("=" * 72)
        print(f"{'#':<4} {'Node ID':<34} {'State':<10} {'RSSI':<9} {'Quality':<8}")
        print("-" * 72)
        
        for i, peer in enumerate(peers, 1):
            node_id = peer.get('node_id', '')
            state = peer.get('state', 'unknown')
            rssi = peer.get('rssi', 0)
            quality = peer.get('quality', 0)
            
            print(f"{i:<4} {node_id:<34} {state:<10} {rssi:>4} dBm {quality:>6.2f}")
        
        print()
        print(f"Tip: Use  meshctl send '#N' \"message\"  to send by peer number")
        
        return 0
    
    def _resolve_recipient(self, recipient: str) -> Optional[str]:
        """Resolve a recipient to a full node ID hex string.
        
        Accepts:
          - A peer number like '#1', '#2', etc.
          - A full 32-char hex node ID
          - A partial hex prefix (matches if unambiguous)
        
        Returns:
            Full node ID hex string, or None on error.
        """
        # Peer number shorthand: #1, #2, ...
        if recipient.startswith('#'):
            try:
                peer_num = int(recipient[1:])
            except ValueError:
                print(f"Error: Invalid peer number '{recipient}'", file=sys.stderr)
                return None
            
            try:
                result = self.client.call("peers")
            except Exception as e:
                print(f"Failed to fetch peers: {e}", file=sys.stderr)
                return None
            
            peers = result.get('peers', [])
            if peer_num < 1 or peer_num > len(peers):
                print(f"Error: Peer #{peer_num} not found (have {len(peers)} peers)", file=sys.stderr)
                return None
            
            node_id = peers[peer_num - 1].get('node_id', '')
            print(f"Resolved #{peer_num} -> {node_id}")
            return node_id
        
        # If it looks like a valid full hex ID, use it directly
        try:
            bytes.fromhex(recipient)
            if len(recipient) == 32:
                return recipient
        except ValueError:
            pass
        
        # Try partial prefix match against known peers
        try:
            result = self.client.call("peers")
        except Exception as e:
            print(f"Failed to fetch peers: {e}", file=sys.stderr)
            return None
        
        peers = result.get('peers', [])
        matches = [p for p in peers if p.get('node_id', '').startswith(recipient)]
        
        if len(matches) == 1:
            node_id = matches[0].get('node_id', '')
            print(f"Resolved prefix '{recipient}' -> {node_id}")
            return node_id
        elif len(matches) > 1:
            print(f"Error: Ambiguous prefix '{recipient}' matches {len(matches)} peers:", file=sys.stderr)
            for m in matches:
                print(f"  {m.get('node_id', '')}", file=sys.stderr)
            return None
        
        # No match found -- return as-is and let the daemon validate
        return recipient
    
    def regions(self) -> int:
        """Show region topology."""
        try:
            result = self.client.call("regions")
        except RPCError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Failed to connect to sparkd: {e}", file=sys.stderr)
            return 1
        
        regions = result.get('regions', [])
        
        if not regions:
            print("No regions detected")
            return 0
        
        print(f"Known Regions ({len(regions)})")
        print("=" * 60)
        print(f"{'Region ID':<36} {'Local':<8} {'SubMesh':<10} {'Gateways':<10}")
        print("-" * 60)
        
        for region in regions:
            region_id = region.get('region_id', '')[:32] + "..."
            is_local = "YES" if region.get('is_local') else "no"
            submeshes = region.get('submesh_count', 0)
            gateways = region.get('gateway_count', 0)
            
            print(f"{region_id:<36} {is_local:<8} {submeshes:<10} {gateways:<10}")
        
        return 0
    
    def routes(self) -> int:
        """Display routing table."""
        try:
            result = self.client.call("routes")
        except RPCError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Failed to connect to sparkd: {e}", file=sys.stderr)
            return 1
        
        routes = result.get('routes', [])
        
        if not routes:
            print("No routes in table")
            return 0
        
        print(f"Routing Table ({len(routes)} entries)")
        print("=" * 80)
        print(f"{'Destination':<36} {'Next Hop':<36} {'Hops':<6}")
        print("-" * 80)
        
        for route in routes:
            dest = route.get('dest', '')[:32] + "..."
            next_hop = route.get('next_hop', '')[:32] + "..."
            hops = route.get('hops', 0)
            
            print(f"{dest:<36} {next_hop:<36} {hops:<6}")
        
        return 0
    
    def send(self, recipient: str, message: str, no_wait: bool = False) -> int:
        """Send a message.
        
        Recipient can be:
          - '#1', '#2', etc. to select by peer number
          - A hex prefix that uniquely matches a peer
          - A full 32-char hex node ID
        """
        # Resolve recipient to full node ID
        resolved = self._resolve_recipient(recipient)
        if resolved is None:
            return 1
        
        try:
            result = self.client.call("send", {
                "recipient": resolved,
                "message": message,
            })
        except RPCError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Failed to connect to sparkd: {e}", file=sys.stderr)
            return 1
        
        if "error" in result:
            print(f"Error: {result['error']}", file=sys.stderr)
            return 1
        
        mode = result.get('mode', 'unknown')
        message_id = result.get('message_id', '')
        fragments = result.get('fragments', 1)
        onion_layers = result.get('onion_layers', 0)
        
        # Build mode description
        if mode == "onion" and onion_layers:
            mode_desc = f"onion, {onion_layers}-layer"
        elif fragments > 1:
            mode_desc = f"{mode}, {fragments} fragments"
        else:
            mode_desc = mode
        
        print(f"Message sent ({mode_desc})")
        print(f"  To: {resolved}")
        print(f"  ID: {message_id}")
        print(f"  Status: {result.get('status', 'unknown')}")
        
        # Wait for delivery receipt unless --no-wait
        if no_wait or not message_id:
            return 0
        
        return self._wait_for_delivery(message_id)
    
    def _wait_for_delivery(self, message_id: str, timeout: int = 10) -> int:
        """Poll for a delivery receipt.
        
        Args:
            message_id: Hex message ID to check
            timeout: Max seconds to wait
            
        Returns:
            0 on delivery confirmed, 0 on timeout (message may still arrive)
        """
        print("Waiting for delivery receipt...", end="", flush=True)
        
        deadline = time.time() + timeout
        poll_interval = 0.5  # Start at 500ms
        
        while time.time() < deadline:
            time.sleep(poll_interval)
            
            try:
                status = self.client.call("message_status", {"message_id": message_id})
            except Exception:
                # Connection hiccup -- keep trying
                poll_interval = min(poll_interval * 1.5, 2.0)
                continue
            
            delivery_status = status.get("status", "unknown")
            
            if delivery_status == "acknowledged":
                print("\rDelivery confirmed!                ")
                return 0
            elif delivery_status in ("failed", "expired"):
                print(f"\rDelivery {delivery_status}                ")
                return 1
            
            # Still pending/sent -- keep polling
            poll_interval = min(poll_interval * 1.2, 2.0)
        
        print("\rNo delivery receipt yet (recipient may be out of range)")
        return 0
    
    def _resolve_message(self, identifier: str) -> Optional[str]:
        """Resolve a message identifier to a full message ID hex string.
        
        Accepts:
          - An inbox number like '#1', '#2', etc.
          - A full 32-char hex message ID
          - A partial hex prefix (matches if unambiguous)
        
        Returns:
            Full message ID hex string, or None on error.
        """
        # Fetch the inbox so we can resolve numbers and prefixes
        try:
            result = self.client.call("inbox", {"limit": 100})
        except Exception as e:
            print(f"Failed to fetch inbox: {e}", file=sys.stderr)
            return None
        
        messages = result.get('messages', [])
        
        # Inbox number shorthand: #1, #2, ...
        if identifier.startswith('#'):
            try:
                msg_num = int(identifier[1:])
            except ValueError:
                print(f"Error: Invalid message number '{identifier}'", file=sys.stderr)
                return None
            
            if msg_num < 1 or msg_num > len(messages):
                print(f"Error: Message #{msg_num} not found (have {len(messages)} messages)", file=sys.stderr)
                return None
            
            msg_id = messages[msg_num - 1].get('message_id', '')
            return msg_id
        
        # Full hex ID
        try:
            bytes.fromhex(identifier)
            if len(identifier) == 32:
                return identifier
        except ValueError:
            pass
        
        # Partial prefix match
        matches = [m for m in messages if m.get('message_id', '').startswith(identifier)]
        
        if len(matches) == 1:
            return matches[0].get('message_id', '')
        elif len(matches) > 1:
            print(f"Error: Ambiguous prefix '{identifier}' matches {len(matches)} messages:", file=sys.stderr)
            for m in matches:
                print(f"  {m.get('message_id', '')}", file=sys.stderr)
            return None
        
        # No match -- return as-is and let the daemon validate
        return identifier
    
    def read(self, identifier: str) -> int:
        """Read a message by ID, number, or hex prefix."""
        resolved = self._resolve_message(identifier)
        if resolved is None:
            return 1
        
        try:
            result = self.client.call("read_message", {"message_id": resolved})
        except RPCError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Failed to connect to sparkd: {e}", file=sys.stderr)
            return 1
        
        if "error" in result:
            print(f"Error: {result['error']}", file=sys.stderr)
            return 1
        
        received = result.get('received_at', 0)
        if received:
            received_str = datetime.fromtimestamp(received).strftime("%Y-%m-%d %H:%M:%S")
        else:
            received_str = "unknown"
        
        print(f"Message ID:  {result.get('message_id', '')}")
        print(f"Received:    {received_str}")
        print(f"Size:        {result.get('payload_size', 0)} bytes")
        print("-" * 40)
        
        text = result.get('payload_text')
        if text is not None:
            print(text)
        else:
            print(f"[binary data: {result.get('payload_hex', '')}]")
        
        return 0
    
    def inbox(self, limit: int = 20, clear: bool = False, delete: Optional[str] = None) -> int:
        """Check inbox, optionally clear all or delete a specific message."""
        # Handle --clear
        if clear:
            try:
                result = self.client.call("clear_inbox", {})
            except RPCError as e:
                print(f"Error: {e.message}", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"Failed to connect to sparkd: {e}", file=sys.stderr)
                return 1
            
            count = result.get('deleted', 0)
            print(f"Cleared {count} message(s) from inbox")
            return 0
        
        # Handle --delete <id>
        if delete:
            resolved = self._resolve_message(delete)
            if resolved is None:
                return 1
            
            try:
                result = self.client.call("delete_message", {"message_id": resolved})
            except RPCError as e:
                print(f"Error: {e.message}", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"Failed to connect to sparkd: {e}", file=sys.stderr)
                return 1
            
            if "error" in result:
                print(f"Error: {result['error']}", file=sys.stderr)
                return 1
            
            print(f"Deleted message {resolved}")
            return 0
        
        # Default: list inbox
        try:
            result = self.client.call("inbox", {"limit": limit})
        except RPCError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Failed to connect to sparkd: {e}", file=sys.stderr)
            return 1
        
        messages = result.get('messages', [])
        
        if not messages:
            print("Inbox is empty")
            return 0
        
        print(f"Inbox ({len(messages)} messages)")
        print("=" * 78)
        print(f"{'#':<4} {'Message ID':<34} {'From':<18} {'Received':<20} {'Size':<6}")
        print("-" * 78)
        
        for i, msg in enumerate(messages, 1):
            msg_id = msg.get('message_id', '')
            sender = msg.get('sender_id', '')[:16] + '..'
            received = msg.get('received_at', 0)
            size = msg.get('payload_size', 0)
            
            if received:
                received_str = datetime.fromtimestamp(received).strftime("%Y-%m-%d %H:%M:%S")
            else:
                received_str = "unknown"
            
            print(f"{i:<4} {msg_id:<34} {sender:<18} {received_str:<20} {size:>4} B")
        
        print()
        print("Tip: Use  meshctl read '#1'  to read the first message")
        
        return 0
    
    def debug(self) -> int:
        """Show debug information."""
        try:
            result = self.client.call("debug")
        except RPCError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Failed to connect to sparkd: {e}", file=sys.stderr)
            return 1
        
        print("Debug Information")
        print("=" * 60)
        print(json.dumps(result, indent=2, default=str))
        
        return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SPARK Mesh Router CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  status      Show node status
  peers       List discovered peers
  regions     Show region topology
  routes      Display routing table
  send        Send a message
  inbox       Check inbox
  read        Read a message
  debug       Show debug information

Examples:
  meshctl status
  meshctl peers
  meshctl send '#1' "Hello, mesh!"
  meshctl send 0e6c78 "Hello!"
  meshctl send 0e6c7822f3f0c212b157e7de8550e6e9 "Full ID"
  meshctl inbox
  meshctl read '#1'
  meshctl inbox --clear
  meshctl inbox --delete '#2'
""",
    )
    
    parser.add_argument(
        "-s", "--socket",
        type=Path,
        default=DEFAULT_SOCKET,
        help="Path to sparkd socket",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # status command
    subparsers.add_parser("status", help="Show node status")
    
    # peers command
    subparsers.add_parser("peers", help="List discovered peers")
    
    # regions command
    subparsers.add_parser("regions", help="Show region topology")
    
    # routes command
    subparsers.add_parser("routes", help="Display routing table")
    
    # send command
    send_parser = subparsers.add_parser("send", help="Send a message")
    send_parser.add_argument(
        "recipient",
        help="Recipient: peer number (#1), hex prefix, or full node ID",
    )
    send_parser.add_argument("message", help="Message to send")
    send_parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Don't wait for delivery receipt",
    )
    
    # inbox command
    inbox_parser = subparsers.add_parser("inbox", help="Check inbox")
    inbox_parser.add_argument(
        "-n", "--limit",
        type=int,
        default=20,
        help="Maximum messages to show",
    )
    inbox_parser.add_argument(
        "--clear",
        action="store_true",
        help="Delete all messages from inbox",
    )
    inbox_parser.add_argument(
        "--delete",
        metavar="ID",
        help="Delete a specific message (#N, hex prefix, or full ID)",
    )
    
    # read command
    read_parser = subparsers.add_parser("read", help="Read a message")
    read_parser.add_argument(
        "message",
        help="Message to read: inbox number (#1), hex prefix, or full message ID",
    )
    
    # debug command
    subparsers.add_parser("debug", help="Show debug information")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Create CLI instance
    cli = MeshCtl(args.socket)
    
    # Dispatch command
    if args.command == "status":
        return cli.status()
    elif args.command == "peers":
        return cli.peers()
    elif args.command == "regions":
        return cli.regions()
    elif args.command == "routes":
        return cli.routes()
    elif args.command == "send":
        return cli.send(args.recipient, args.message, no_wait=args.no_wait)
    elif args.command == "inbox":
        return cli.inbox(args.limit, clear=args.clear, delete=args.delete)
    elif args.command == "read":
        return cli.read(args.message)
    elif args.command == "debug":
        return cli.debug()
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
