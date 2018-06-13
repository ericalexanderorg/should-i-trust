import requests
import argparse
import os
import socket
import json
import time
import thread

class Inspect(object):
    def __init__(self,domain,working_dir,settings_file):
        self.domain = domain
        self.working_dir = working_dir
        self.output = "Domain: %s\n" % self.domain
        # Load censys_uid and censys_secret
        with open(settings_file) as json_data:
            self.settings = json.load(json_data)

        self.check_bugbounty(self.domain)
        self.check_google_transparency(domain)
        self.check_censys(domain)
        self.check_github(domain)
        self.check_bitbucket(domain) 
        self.check_gitlab(domain)
        self.check_virus_total(domain)
        print("Generating Report...\n\n\n")
        print(self.output)

    def prompt(self, prompt_string):
        while True:
            user_input = raw_input(prompt_string + "\n[y/n]:")
            if user_input == "y":
                return True
            elif user_input == "n":
                return False

    def check_port(self, domain):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((domain,443))
            if result == 0:
                return True
            else: 
                return False
        except:
            return False

    def check_virus_total(self, domain):
        print("Checking VirusTotal:\n")
        self.output += "\n\nVirusTotal:\n"
        url = "https://www.virustotal.com/vtapi/v2/domain/report"
        url = url + "?domain=%s&apikey=%s" % (domain, self.settings["virus_total_key"])
        
        # Check if we already have VirusTotal data for this domain and retrieve if not
        vt_file = os.path.join(self.working_dir, domain + ".vt")
        if not os.path.exists(vt_file):
            r = requests.get(url)
            if r.status_code == 200:
                open(vt_file, 'wb').write(r.content)
            else:
                print "error occurred: %s" % r.content
                return

        with open(vt_file) as json_data:
            vt_data = json.load(json_data)

        if 'detected_downloaded_samples' in vt_data:
            self.output += "\tDetected Samples:\n" 
            for sample in vt_data["detected_downloaded_samples"]:
                self.output += "\t\tSHA256: %s\n" % (sample["sha256"])
                self.output += "\t\t\tDate: %s\n" % (sample["date"])
                self.output += "\t\t\tHits: %s/%s\n" % (sample["positives"], sample["total"])
        if 'Malwarebytes hpHosts info' in vt_data:
            self.output += "\tMalwarebytes hpHosts info: %s\n" % (vt_data["Malwarebytes hpHosts info"])
        if 'Websense ThreatSeeker category' in vt_data:
            self.output += "\tWebsense ThreatSeeker category: %s\n" % (vt_data["Websense ThreatSeeker category"])
        if 'Webutation domain info' in vt_data:
            self.output += "\tWebutation Verdict: %s\n" % (vt_data["Webutation domain info"]["Verdict"])
        if 'BitDefender category' in vt_data:
            self.output += "\tBitDefender category: %s\n" % (vt_data["BitDefender category"])

        if 'subdomains' in vt_data:
            self.output += "\tSub Domains:\n"
            for subdomain in vt_data["subdomains"]:
                self.output += "\t\t%s\n" % (subdomain)

        

    def check_gitlab(self, domain):
        print("Checking GitLab:\n")
        self.output += "\n\nGitLab:\n"
        url = "https://gitlab.com/api/v4/projects?search="
        # remove tld from domain
        q = domain.split(".")[0]
        url = url + q
        r = requests.get(url)
        json_dict = json.loads(r.content)
        for items in json_dict:
            if items["description"] and items["web_url"]:
                self.output += "\t" + items["description"] + "\n\t\t(" + items["web_url"] + ")\n"

    def check_bitbucket(self, domain):
        try: 
            print("Checking BitBucket:\n")
            self.output += "\n\nBitBucket:\n"
            url = "https://bitbucket.org/api/1.0/users/"
            # remove tld from domain
            q = domain.split(".")[0]
            url = url + q
            r = requests.get(url)
            json_dict = json.loads(r.content)
            if 'repos' in json_dict:
                for repos in json_dict["repositories"]:
                    if items["slug"]:
                        self.output += "\t" + items["slug"] + ")\n"
        except:
            print("Error Processing BitBucket")

    def check_github(self, domain):
        print("Checking GitHub:\n")
        self.output += "\n\nGitHub:\n"
        url = "https://api.github.com/search/repositories?q="
        # remove tld from domain
        q = domain.split(".")[0]
        url = url + q
        r = requests.get(url)
        json_dict = json.loads(r.content)
        for items in json_dict["items"]:
            if items["description"] and items["html_url"]:
                self.output += "\t" + items["description"] + "\n\t\t(" + items["html_url"] + ")\n"
            
            
    def check_google_transparency(self, domain):
        print("Checking Google Certificate Transparency Search:\n")
        url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=false&include_subdomains=true&domain=%s" % domain
        r = requests.get(url)
        # Gibberish in first two lines, remove it
        tmp_list = r.content.split("\n")[2:]
        json_string = ''.join(tmp_list)
        json_dict = json.loads(json_string)
        self.output += "\nGoogle Cert Transparency Report Findings:\n"
        uniq_name_list = []

        for entry in json_dict[0][1]:
            #serial = entry[0]
            name = entry[1]
            #ca = entry[2]
            #valid_from = time.strftime('%Y-%m-%d', time.gmtime(entry[3]/1000))
            #valid_to = time.strftime('%Y-%m-%d', time.gmtime(entry[4]/1000))
            #google_id = entry[5]
            if name not in uniq_name_list:
                uniq_name_list.append(name)
        
        ssl_labs_check = self.prompt("Check SSL Labs grade for %s found certificates?\nTakes about 5 minutes each cert" % (str(len(uniq_name_list))))
        for name in uniq_name_list:
            self.output += "\t" + name
            if ssl_labs_check:
                if name.startswith("*."):
                    print("Found a wildcard cert, checking if base domain supports HTTPS")
                    # Check if the base domain is listening on 443
                    if self.check_port(domain):
                        name = domain
                    elif self.check_port("www." + domain):
                        print("Checking if www.%s supports HTTPS" % (domain))
                        name = "www." + domain
                    else:
                        # No luck, got to next record
                        next

                prompt_string = "Check SSL Labs grade for %s?:" % name
                if self.prompt(prompt_string):
                    self.check_ssllabs(name)
                    self.output += "\n"
                else:
                    self.output += " (SSL Labs _not_ checked)\n"
            else:
                self.output += " (SSL Labs _not_ checked)\n"


    def check_bugbounty(self, domain):
        self.output += "\nBug Bounty: "
        bug_bounty = False
        # Check if they're participating in a bug bounty program
        parent_dir = os.path.abspath(os.path.join(self.working_dir, os.pardir))
        file_path = os.path.join(parent_dir, r'bugbounty.txt')
        if not os.path.exists(file_path):
            # Download a list of of domains participating in bug bounties
            url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt"
            r = requests.get(url)
            open(file_path, 'wb').write(r.content)

        if domain in open(file_path).read():
            bug_bounty = True

        # List doesn't contain all bug bounty domains, this is a hack to fix that
        more_bug_bounties = (
            "google.com"
        )
        if domain in more_bug_bounties:
            bug_bounty = True
        
        if bug_bounty:
            self.output += "Yes\n"
        else:
            self.output += "No\n"


    def check_ssllabs(self, domain):
        # HTTPS check
        endpoint_data = ""
        if self.check_port(domain):
            # Site supports HTTPS, check SSL Labs grade
            response_pending = True
            while response_pending:
                url = ("https://api.ssllabs.com/api/v3/analyze?host=%s" % (domain))
                r = requests.get(url)
                api_json = json.loads(r.content)
                if api_json["status"]:
                    if api_json["status"] != "READY":
                        print("Waiting for SSL Labs grade for %s" % (domain))
                        time.sleep(60)
                    else:
                        self.output += " (SSL Labs:%s)" % (api_json["endpoints"][0]["grade"])
                        return
            self.output += "SSL Labs grade for %s:" % (domain)
            print(endpoint_data)
        else:
            self.output += "(HTTPS Not Supported)"


    def check_censys(self, domain):
        self.output += "\nCensys Data:\n"
        API_URL = "https://censys.io/api/v1"

        if not self.settings["censys_uid"]:
            # No censys settings, exit
            return

        # Check if we already have censys data for this domain and retrieve if not
        censys_file = os.path.join(self.working_dir, domain + ".censys")
        if not os.path.exists(censys_file):
            params = {"query" : domain}
            r = requests.post(API_URL + "/search/ipv4", json = params, auth=(self.settings["censys_uid"], self.settings["censys_secret"]))
            if r.status_code == 200:
                open(censys_file, 'wb').write(r.content)
            else:
                print "error occurred: %s" % r.content
                return

        with open(censys_file) as json_data:
            censys_data = json.load(json_data)

        if int(censys_data["metadata"]["count"]) > 50:
            prompt_string = ("Censys has a monthly limit of 250 queries,"
                                "\nand found %s results for this domain."
                                "\n\nContinue with pulling data on each ip? [y/n]:" 
                                % (censys_data["metadata"]["count"]))
            if not self.prompt(prompt_string):
				return


        port_list = []
        http_titles = []
        for result in censys_data["results"]:
            ip = result["ip"]
            ip_file = os.path.join(self.working_dir, ip + ".censys")
            if not os.path.exists(ip_file):
                r = requests.get(API_URL + "/view/ipv4/" + ip, auth=(self.settings["censys_uid"], self.settings["censys_secret"]))
                if r.status_code == 200:
                    open(ip_file, 'wb').write(r.content)
                else:
                    print "error occurred: %s" % r.content
                    return

            with open(ip_file) as json_data:
                censys_ip_data = json.load(json_data)
                for port in censys_ip_data["ports"]:
                    if port not in port_list:
                        port_list.append(port)

                for port in port_list:
                    port_str = str(port)
                    match_list = ("4", "8", "9")
                    if port_str[0] in match_list:
                        try:
                            title = censys_ip_data[port_str]["http"]["get"]["title"] 
                            if title not in http_titles:
                                http_titles.append(title)
                        except:
                            pass
                
        ports = ""
        for port in port_list:
            ports += str(port) + ","

        self.output += "\tServers found: %s\n" % censys_data["metadata"]["count"]
        self.output += "\tPorts found: %s\n" % ports 
        self.output += "\tPage titles found:\n"
        for title in http_titles:
            self.output += "\t\t" + title + "\n"


if __name__ == "__main__":
    # Gather our arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Domain to evaluate", required=True)
    parser.add_argument("-w", "--workingdir", help="Directory to store temporary files", required=False)
    parser.add_argument("-s", "--settingsfile", help="JSON file to read settings from", required=False)
    args = parser.parse_args()

    # Establish our working directory
    if not args.workingdir:
        current_directory = os.getcwd()
        working_dir = os.path.join(current_directory, r'working')
    else:
        working_dir = args.workingdir

    # Create our working directory if it doesn't exist
    if not os.path.exists(working_dir):
        os.makedirs(working_dir)

    # Reset working directory to the domain we're searching, and create
    working_dir = os.path.join(working_dir, args.domain)
    if not os.path.exists(working_dir):
        os.makedirs(working_dir)

    # Read our settings file
    if not args.settingsfile:
        current_directory = os.getcwd()
        settings_file = os.path.join(current_directory, r'settings.json')
    else:
        settings_file = args.settingsfile

    # Check if domain is more than base domain
    domain = args.domain
    if domain.count(".") > 1:
        tl = domain.split(".")
        domain = tl[len(tl)-2] + "." + tl[len(tl)-1]
        while True:
            prompt_string = ("Domain submitted is %s\nChange to %s and continue? [y/n]:" % (args.domain, domain))
            user_input = raw_input(prompt_string)
            if user_input == "y":
                break
            elif user_input == "n":
                print("Sorry, I can't process that domain. Bye")
                exit()
        

    # Environment ready, let's inspect
    c = Inspect(args.domain, working_dir, settings_file)








