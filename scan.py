import subprocess
import signal
import sys
import os
from os import walk
import configparser
import json

class Scan:
    def __init__(self, awsconfig, account, nmap_command):
        # self.hostfiles = []
        # self.records = []
        # self.elb_records = []
        self.failed_to_resolve = []
        self.records_to_scan = []
        self.account = account
        self.awsconfig = awsconfig
        self.aws_profiles = self.add_aws_profiles()
        # eip and elb_records are used to store the account EIPs and ELBs
        self.eip = []
        self.elb_records = []
        self.elbv2_records = []
        #account_eip and account_elb are the endpoints to be scanned
        self.account_eip = []
        self.account_elb = []
        self.account_elbv2 = []
        #first validate the nmap command
        self.check_command(nmap_command)
        self.nmap_command = nmap_command
        

    def add_aws_profiles(self):
        """
        add a list of AWS profiles 
        """
      
        config = configparser.ConfigParser()
        config.read(os.path.expanduser(self.awsconfig))
        config_profiles = config.sections()
        config_profiles.remove('default')
        if self.account == None:
            config_profiles = [profile.replace('profile', '').strip() for profile in config_profiles]
        else:
            # config_profiles = [self.account]
            config_profiles = self.account.split(',')


        return config_profiles


    def set_records(self, records):
        self.records = records

    def set_elb_records(self, elb_records):
        self.elb_records = elb_records

    def add_record(self, record):
        if record not in self.records:
            self.records.append(record)

    def add_elb_record(self, record):
        if record not in self.elb_records:
            self.elb_records.append(record)

    def add_failed_to_resolve(self, record):
        if record not in self.failed_to_resolve:
            self.failed_to_resolve.append(record)

    def add_records_to_scan(self, record):
        if record not in self.records_to_scan:
            self.records_to_scan.append(record)

    def sanity_check_record(self,record):
        """
        filter out garbage records
        """
        non_zebedee_domains = ['.acm-validations.aws','dkim.amazonses.com', '.sendgrid.net', '.ghost.io']
        if not any(x in record for x in non_zebedee_domains):
            record = self.cleanRecord(record)           
            self.add_records_to_scan(record)


    def cleanRecord(self, record):
        """
        strip special characters
        """
        record = record.strip('\n')
        if '\n' in record:
            record = record.split('\n')
            record = record[0]
        
        record = record.strip('.')

        return record

    def getFiles(self,file):
        """
        determine if file is a file or directory
        """
        f = []
 
        if os.path.isdir(file):
            #return list of files
            for (dirpath, dirnames, filenames) in walk(file):
                f.extend(filenames)
            self.hostfiles = [dirpath + '/' + x for x in f]
        elif os.path.isfile(file):  
            self.hostfiles = [file]


    def getHosts(self):
        """
        scan a file and return a list of hosts 
        """

        for x in self.hostfiles:
            self.getRecords(x)


    def getRecords(self, fileName):
        """
        return a unique list of records
        """
        with open(fileName) as f:
            records = [line.rstrip() for line in f]

        unique_records = []
        [unique_records.append(x) for x in records if x not in unique_records]
        
        self.records = self.records + unique_records


    def execute_ip_scan(self,ports):
        """
        excecute a scan against an ip with a range of ports
        """
        signal.signal(signal.SIGINT, self.sig_handler)

        for x in self.account_eip:
            print("\n##############################################\n")
            print("name: {}\nenv: {}\nregion: {}\nip: {}\n".format(x['name'], x['env'], x['region'], x['ip'] ))

            result = subprocess.getoutput(self.nmap_command.format(ports, x['ip']))
            if result != "":
                print(result)
            else:
                print("ports {} are unreachable".format(ports))


    def execute_elb_scan(self):
        """
        excecute a scan against an ip with a range of ports
        """
        signal.signal(signal.SIGINT, self.sig_handler)

        for elb in self.account_elb:
            print("\n##############################################\n")
            print("name: {}\ndns: {}\nenv: {}\n".format(elb['name'], elb['dns'], elb['env']))

            ports = [str(x['Listener']['LoadBalancerPort']) for x in elb['listeners']]
            ports = ",".join(ports)
            result = subprocess.getoutput(self.nmap_command.format(ports, elb['dns']))
            
            if result != "":
                print(result)
            else:
                print("ports {} are unreachable".format(ports))


    def execute_elbv2_scan(self):
        """
        excecute a scan against an ip with a range of ports
        """
        signal.signal(signal.SIGINT, self.sig_handler)

        ports  = '80,443'

        for elb in self.account_elbv2:
            print("\n##############################################\n")
            print("name: {}\ndns: {}\nenv: {}\n".format(elb['name'], elb['dns'], elb['env']))

            # ports = [str(x['Listener']['LoadBalancerPort']) for x in elb['listeners']]
            # ports = ",".join(ports)
            result = subprocess.getoutput(self.nmap_command.format(ports, elb['dns']))
            
            if result != "":
                print(result)
            else:
                print("ports {} are unreachable: {}".format(ports, result))

    def sig_handler(self, sig, frame):
        """
        stop program
        """
        print("\nstopping scan")
        sys.exit(0)


    def fetch_public_ip(self):
        """
        fetch all public IP addresses from all regions
        """
        # assign the command to a var and check for malicious content
        aws_fetch_eip_command = "aws ec2 describe-addresses --profile {} --region {}"
        self.check_command(aws_fetch_eip_command)
        aws_fetch_regions_command = "aws ec2 describe-regions"
        self.check_command(aws_fetch_regions_command)

        region_result = json.loads(subprocess.getoutput(aws_fetch_regions_command))
        aws_regions = [x['RegionName'] for x in region_result['Regions']]
        
        for region in aws_regions:
            for profile in self.aws_profiles:
                eip_result = json.loads(subprocess.getoutput(aws_fetch_eip_command.format(profile, region)))
                if len(eip_result['Addresses']) > 0:
                    self.eip.append(eip_result)


    def fetch_elb(self):
        """
        fetch all elb from all regions
        """
        # assign the command to a var and check for malicious content
        aws_fetch_elb_command = "aws elb describe-load-balancers --profile {} --region {}"
        self.check_command(aws_fetch_elb_command)
        aws_fetch_regions_command = "aws ec2 describe-regions"
        self.check_command(aws_fetch_regions_command)

        region_result = json.loads(subprocess.getoutput(aws_fetch_regions_command))
        aws_regions = [x['RegionName'] for x in region_result['Regions']]
        
        for region in aws_regions:
            for profile in self.aws_profiles:
                elb_result = json.loads(subprocess.getoutput(aws_fetch_elb_command.format(profile, region)))
                if len(elb_result['LoadBalancerDescriptions']) > 0:
                    # add the env key to identify the environment
                    for elb in elb_result['LoadBalancerDescriptions']:
                        elb['env'] = profile
                    self.elb_records.append(elb_result)



    def fetch_elbv2(self):
        """
        fetch all elbv2 from all regions
        """
        # assign the command to a var and check for malicious content
        aws_fetch_elb_command = "aws elbv2 describe-load-balancers --profile {} --region {}"
        self.check_command(aws_fetch_elb_command)
        aws_fetch_regions_command = "aws ec2 describe-regions"
        self.check_command(aws_fetch_regions_command)

        region_result = json.loads(subprocess.getoutput(aws_fetch_regions_command))
        aws_regions = [x['RegionName'] for x in region_result['Regions']]
        
        for region in aws_regions:
            for profile in self.aws_profiles:
                elb_result = json.loads(subprocess.getoutput(aws_fetch_elb_command.format(profile, region)))
                if len(elb_result['LoadBalancers']) > 0:
                    # add the env key to identify the environment
                    for elb in elb_result['LoadBalancers']:
                        elb['env'] = profile
                    self.elbv2_records.append(elb_result)


    def check_command(self, command):
        """
        allows to check if a command is intended to create or delete resources
        """
        if 'delete' in command or 'create' in command:
            print("ERROR!!!! We don't allow creating or deleting resources")
            sys.exit(1)


    def add_account_eip(self):
        """
        collect addresses to be scanned
        """
        # default values
        ip_env = ""
        ip_name = ""

        # need to improve this loop
        for addresses in self.eip:
            for ip in addresses['Addresses']:
                if 'Tags' in ip.keys():
                    for tag in ip['Tags']:
                        if tag['Key'].lower() == "env":
                            ip_env = tag['Value']
                        elif tag['Key'].lower() == "name":
                            ip_name = tag['Value']
                self.account_eip.append({'name': ip_name, 'ip':ip['PublicIp'], 'env':ip_env, 'region': ip['NetworkBorderGroup']})


    def add_account_elb(self):
        """
        collect ELBs to be scanned
        """

        for elb_record in self.elb_records:
            for elb in elb_record['LoadBalancerDescriptions']:
                self.account_elb.append({'name': elb['LoadBalancerName'], 'dns':elb['DNSName'], 
                'listeners':elb['ListenerDescriptions'], 'regions': elb['AvailabilityZones'], 'env': elb['env']})


    def add_account_elbv2(self):
        """
        collect ELBs to be scanned
        """

        for elb_record in self.elbv2_records:
            for elb in elb_record['LoadBalancers']:
                self.account_elbv2.append({'name': elb['LoadBalancerName'], 'dns':elb['DNSName'], 
                'regions': elb['AvailabilityZones'], 'env': elb['env']})
    