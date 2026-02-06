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
    meshctl debug       - Show debug information
"""

import sys
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
        print("=" * 70)
        print(f"{'Node ID':<36} {'State':<12} {'RSSI':<8} {'Quality':<8}")
        print("-" * 70)
        
        for peer in peers:
            node_id = peer.get('node_id', '')[:32] + "..."
            state = peer.get('state', 'unknown')
            rssi = peer.get('rssi', 0)
            quality = peer.get('quality', 0)
            
            print(f"{node_id:<36} {state:<12} {rssi:>4} dBm {quality:>6.2f}")
        
        return 0
    
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
    
    def send(self, recipient: str, message: str) -> int:
        """Send a message."""
        try:
            result = self.client.call("send", {
                "recipient": recipient,
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
        
        print(f"Message sent")
        print(f"  ID: {result.get('message_id', 'unknown')}")
        print(f"  Status: {result.get('status', 'unknown')}")
        
        return 0
    
    def inbox(self, limit: int = 20) -> int:
        """Check inbox."""
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
        print("=" * 60)
        
        for msg in messages:
            msg_id = msg.get('message_id', '')[:16] + "..."
            received = msg.get('received_at', 0)
            size = msg.get('payload_size', 0)
            
            if received:
                received_str = datetime.fromtimestamp(received).strftime("%Y-%m-%d %H:%M:%S")
            else:
                received_str = "unknown"
            
            print(f"{msg_id}  {received_str}  {size} bytes")
        
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
  debug       Show debug information

Examples:
  meshctl status
  meshctl peers
  meshctl send abc123def456... "Hello, mesh!"
  meshctl inbox
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
    send_parser.add_argument("recipient", help="Recipient node ID (hex)")
    send_parser.add_argument("message", help="Message to send")
    
    # inbox command
    inbox_parser = subparsers.add_parser("inbox", help="Check inbox")
    inbox_parser.add_argument(
        "-n", "--limit",
        type=int,
        default=20,
        help="Maximum messages to show",
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
        return cli.send(args.recipient, args.message)
    elif args.command == "inbox":
        return cli.inbox(args.limit)
    elif args.command == "debug":
        return cli.debug()
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
