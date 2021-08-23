#!/usr/bin/env python3


import argparse
from scan import Scan
import subprocess
import sys
import os
from os import walk
import configparser


def scan_ip_addresses(scan,ports):
    """
    scan ip addresses
    """
    scan.fetch_public_ip()
    scan.add_account_eip()
    scan.execute_ip_scan(ports)


def scan_elb_records(scan):
    """
    scan elb records
    """
    scan.fetch_elbv2()
    scan.add_account_elbv2()
    scan.execute_elbv2_scan()

    scan.fetch_elb()
    scan.add_account_elb()
    scan.execute_elb_scan()

def main():

    parser = argparse.ArgumentParser(description='Script for collecting and scanning for open ports')
    parser.add_argument('--ports', help='Ports to scan', required=False, default='22,80,443,9735')
    parser.add_argument('--awsconfig', help='AWS config to use for authentication', required=False, default='~/.aws/config')
    parser.add_argument('--account', help='comma separated list of accounts to scan, i.e. dev,tools,zapdos', required=False, default=None)
    parser.add_argument('--nmapcommand', help='nmap command to run', required=False, default="nmap -sT -Pn -p {} {} | grep open")
    parser.add_argument('--scan', help='Scan IP addresses or ELB records.  Use ip or elb', required=True) 

    args = parser.parse_args()

    scan = Scan(args.awsconfig, args.account, args.nmapcommand)

    if args.scan.lower() == "ip":
        print("scanning IP addresses")
        scan_ip_addresses(scan, args.ports)
    elif args.scan.lower() == "elb":
        print("scanning ELB records")
        scan_elb_records(scan)
    else:
        print("a valid scan is required, ip or elb")


if __name__ == "__main__":
    main()
