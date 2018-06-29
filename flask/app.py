from flask import Flask, request, redirect, url_for, send_from_directory, render_template
import requests
import argparse
import os
import socket
import json
import time
import thread
#import domain_inspect

app = Flask(__name__)

@app.route("/")
def root():
    return app.send_static_file('index.html')

@app.route('/domain/<domain>')
def domain_content(domain):
    c = domain_inspect(domain, "working/domains", "settings.json")
    domain_data = c.check_all()
    return render_template('domain.html', domain = domain, domain_data = domain_data)

#@app.route('/domain/search/<domain>')
#def domain_search(domain):
#    return "success"

@app.route("/menu")
def menu():
    return_string = ''
    for d in os.listdir("working/domains"):
        if "bugbounty.txt" not in d:
            return_string += "<li><a href='#' class='sidebar-link' domain='%s'>%s</a></li>" % (d,d)
    return return_string

class domain_inspect(object):
    def __init__(self,domain,working_dir,settings_file):
        self.domain = domain
        self.working_dir = os.path.join(working_dir, domain)
        if not (os.path.exists(self.working_dir)):
            os.makedirs(self.working_dir)
        self.output = "Domain: %s\n" % self.domain
        # Load censys_uid and censys_secret
        with open(settings_file) as json_data:
            self.settings = json.load(json_data)

        self.return_data = {}
        

    def check_all(self):
        self.check_bugbounty(self.domain)
        self.check_google_transparency(self.domain)
        self.check_censys(self.domain)
        self.check_github(self.domain)
        self.check_bitbucket(self.domain) 
        self.check_gitlab(self.domain)
        self.check_virus_total(self.domain)
        #print(json.dumps(self.return_data))
        return self.return_data


    def prompt(self, prompt_string):
        return False
        #while True:
        #    user_input = raw_input(prompt_string + "\n[y/n]:")
        #    if user_input == "y":
        #        return True
        #   elif user_input == "n":
        #       return False

    def add_sub_domains(self, new_sub_domain_list):
        # Check if we already have a sub_domains key in our return dict
        if 'sub_domains' in self.return_data:
            old_sub_domain_list = self.return_data['sub_domains']
            for sub_domain in old_sub_domain_list:
                new_sub_domain_list.append(sub_domain)
        new_sub_domain_list.sort()
        # Remove duplicates
        old_sub_domain_list = new_sub_domain_list
        new_sub_domain_list = []
        for domain in old_sub_domain_list:
            if (domain not in new_sub_domain_list and not domain.startswith("*")):
                new_sub_domain_list.append(domain)
        self.return_data['sub_domains'] = new_sub_domain_list

    def add_ip(self, ip, port):
        # Check if ports key exists and add if not
        try:
            x = self.return_data['ports']
        except:
            self.return_data['ports'] = {}
        # Check if this port exists in ports
        try:
            x = self.return_data['ports'][port]
        except:
            self.return_data['ports'][port] = []
        # Add this ip/port
        self.return_data['ports'][port].append(ip)


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
        #print("Checking VirusTotal:\n")
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
            #self.output += "\tMalwarebytes hpHosts info: %s\n" % (vt_data["Malwarebytes hpHosts info"])
            self.return_data['malwarebytes_hphosts_info'] = vt_data["Malwarebytes hpHosts info"]
        if 'Websense ThreatSeeker category' in vt_data:
            #self.output += "\tWebsense ThreatSeeker category: %s\n" % (vt_data["Websense ThreatSeeker category"])
            self.return_data['websense_threatseeker_category'] = vt_data["Websense ThreatSeeker category"]
        if 'Webutation domain info' in vt_data:
            #self.output += "\tWebutation Verdict: %s\n" % (vt_data["Webutation domain info"]["Verdict"])
            self.return_data['webutation_verdict'] = vt_data["Webutation domain info"]["Verdict"]
        if 'BitDefender category' in vt_data:
            #self.output += "\tBitDefender category: %s\n" % (vt_data["BitDefender category"])
            self.return_data['bitdefender_category'] = vt_data["BitDefender category"]

        if 'subdomains' in vt_data:
            subdomain_list = []
            for subdomain in vt_data["subdomains"]:
                subdomain_list.append(subdomain)
            self.add_sub_domains(subdomain_list)

    def check_gitlab(self, domain):
        #print("Checking GitLab:\n")
        self.output += "\n\nGitLab:\n"
        gitlab_file = os.path.join(self.working_dir, domain + ".gitlab")
        if not os.path.exists(gitlab_file):
            url = "https://gitlab.com/api/v4/projects?search="
            # remove tld from domain
            q = domain.split(".")[0]
            url = url + q
            r = requests.get(url)
            json_dict = json.loads(r.content)
            open(gitlab_file, 'wb').write(r.content)
        else:
            with open(gitlab_file) as data_file:
                json_dict = json.load(data_file)
        for items in json_dict:
            if items["description"] and items["web_url"]:
                #self.output += "\t" + items["description"] + "\n\t\t(" + items["web_url"] + ")\n"
                temp_dict = {}
                temp_dict['web_url'] = items["web_url"]
                temp_dict['description'] = items["description"]
                if 'gitlab' in self.return_data:
                    temp_list = self.return_data['gitlab']
                    temp_list.append(temp_dict)
                    self.return_data['gitlab'] = temp_list
                else:
                    self.return_data['gitlab'] = []
                    self.return_data['gitlab'].append(temp_dict)


    def check_bitbucket(self, domain):
        try: 
            #print("Checking BitBucket:\n")
            self.output += "\n\nBitBucket:\n"
            bitbucket_file = os.path.join(self.working_dir, domain + ".bitbucket")
            if not os.path.exists(bitbucket_file):
                print("DownloadingBitBucket:\n")
                url = "https://bitbucket.org/api/1.0/users/"
                # remove tld from domain
                q = domain.split(".")[0]
                url = url + q
                print(url)
                r = requests.get(url)
                if r.content == "None":
                    # BB sends back "None" when there's no results
                    json_dict = json.loads('{"results": null}')
                else:
                    json_dict = json.loads(r.content)
                open(bitbucket_file, 'wb').write(r.content)
            else:
                with open(bitbucket_file) as data_file:
                    json_dict = json.load(data_file)
            if 'repos' in json_dict:
                for repos in json_dict["repositories"]:
                    if items["slug"]:
                        #self.output += "\t" + items["slug"] + ")\n"
                        if 'bitbucket' in self.return_data:
                            self.return_data['bitbucket'].append(items['slug'])
                        else: 
                            self.return_data['bitbucket'] = []
                            self.return_data['bitbucket'].append(items['slug'])

        except ValueError as ve:
            print(ve)

    def check_github(self, domain):
        #print("Checking GitHub:\n")
        self.output += "\n\nGitHub:\n"
        github_file = os.path.join(self.working_dir, domain + ".github")
        if not os.path.exists(github_file):
            url = "https://api.github.com/search/repositories?q="
            # remove tld from domain
            q = domain.split(".")[0]
            url = url + q
            r = requests.get(url)
            json_dict = json.loads(r.content)
            open(github_file, 'wb').write(r.content)
        else:
            with open(github_file) as data_file:
                json_dict = json.load(data_file)
        for items in json_dict["items"]:
            if items["description"] and items["html_url"]:
                #self.output += "\t" + items["description"] + "\n\t\t(" + items["html_url"] + ")\n"
                temp_dict = {}
                temp_dict['web_url'] = items["html_url"]
                temp_dict['description'] = items["description"]
                if 'github' in self.return_data:
                    temp_list = self.return_data['github']
                    temp_list.append(temp_dict)
                    self.return_data['github'] = temp_list
                else:
                    self.return_data['github'] = []
                    self.return_data['github'].append(temp_dict)
            
            
    def check_google_transparency(self, domain):
        #print("Checking Google Certificate Transparency Search:\n")
        google_file = os.path.join(self.working_dir, domain + ".google")
        if not os.path.exists(google_file):
            url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=false&include_subdomains=true&domain=%s" % domain
            r = requests.get(url)
            # Gibberish in first two lines, remove it
            tmp_list = r.content.split("\n")[2:]
            json_string = ''.join(tmp_list)
            open(google_file, 'wb').write(json_string)
            json_dict = json.loads(json_string)
        else:
            with open(google_file) as data_file:
                json_dict = json.load(data_file)
            
        #self.output += "\nGoogle Cert Transparency Report Findings:\n"
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

        self.add_sub_domains(uniq_name_list)
        
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
        #self.output += "\nBug Bounty: "
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
            #self.output += "Yes\n"
            self.return_data['bug_bounty'] = "Yes"
        else:
            #self.output += "No\n"
            self.return_data['bug_bounty'] = "No"


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
        #self.output += "\nCensys Data:\n"
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

        for result in censys_data["results"]:
            ip = result["ip"]
            protocols = result["protocols"]
            for port in protocols:
                p = port.split("/")[0]
                self.add_ip(ip, p)

if __name__ == '__main__':
    # Creating our working folders
    if not (os.path.exists("working/domains")):
        os.makedirs("working/domains")

    # Verify our settings file exists
    if not (os.path.exists("settings.json")):
        print("Can't find settings file, exiting")
        exit()

    # Start our web server
    app.run(debug=True, host='0.0.0.0', port=8080)
