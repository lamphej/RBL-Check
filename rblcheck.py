import json
import optparse, urllib, urllib2, threading, ipaddr
import os
import random
import re
import sys
import traceback
import bs4

class Checker(threading.Thread):
    ThreadID = 0

    def __init__(self, threadid):
        threading.Thread.__init__(self)
        self.ThreadID = threadid

    def run(self):
        global rules
        while len(ip_addresses) > 0:
            current_ip = ip_addresses.pop(0)
            self.threadstatus("Checking %s" % current_ip)
            try:
                opener = BuildOpener()
                rbl_url = "http://multirbl.valli.org/lookup/%s.html" % current_ip
                rbl_page = opener.open(rbl_url, timeout=30).read()
                sessionHash = re.search("sessionHash\":.\"([^\"]*)\"", rbl_page).group(1)
                rbl_page = bs4.BeautifulSoup(rbl_page)
                rbl_tests = rbl_page.findAll("tr", attrs={
                    "id": re.compile("DNSBLBlacklistTest_")
                })
                rbl_tests = [
                    (
                        test.attrs["id"],
                        test.findNext("td", attrs={
                            "class": "l_id"
                        }).text, test.findNext("td", attrs={
                            "class": "dns_zone"
                        }).text,
                        test.findNext("td", attrs={
                            "class": "l_qhost"
                        }).text
                    ) for test in rbl_tests
                ]
                status = "Clean"
                listed_in = []
                for test in rbl_tests:
                    if test[2] in dns_zones:
                        rbl_request = urllib2.Request("http://multirbl.valli.org/json-lookup.php",
                                                      data=urllib.urlencode({"ash": sessionHash,
                                                                            "rid": test[0],
                                                                            "lid": test[1],
                                                                            "q": test[3]
                                                      }),
                                                      headers={"Accept": "application/json, text/javascript, */*; q=0.01",
                                                                "Referer": rbl_url,
                                                                "X-Requested-With": "XMLHttpRequest"
                                                      })
                        rbl_response = json.loads(opener.open(rbl_request, timeout=30).read())
                        if "failed" in rbl_response.keys() and rbl_response["failed"]:
                            listed_in.append("%s (test failed)" % test[2])
                        elif rbl_response["data"]["listed"]:
                            if status == "Clean":
                                status = "Bad"
                            listed_in.append(test[2])
                output_line = "%s,%s,%s,%s,%s\n" % (current_ip,
                                                    '|'.join([rbl for rbl in rules["Major"] if rbl in listed_in]),
                                                    '|'.join([rbl for rbl in rules["Critical"] if rbl in listed_in]),
                                                    '|'.join([rbl for rbl in rules["Damaged"] if rbl in listed_in]),
                                                    status)
                WriteLine("Results.csv", output_line)
            except:
                print traceback.print_exc(file=sys.stdout)
                self.threadstatus("Error during check on %s" % current_ip)

    def threadstatus(self, status):
        print "[%s] - %s" % (self.ThreadID, status)

def BuildOpener():
    opener = urllib2.build_opener()
    opener.addheaders = [("Accept", "*/*"),
                         ("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7"),
                         ("Accept-Language", "en-US,en;q=0.5"),
                         ("User-Agent", random.sample(useragents, 1)[0])]
    return opener


def LoadRules():
    global rules, dns_zones
    for rule_file in os.listdir("Rules"):
        ruleName = rule_file.split('.')[0]
        rules[ruleName] = []
        rule_lines = open("Rules\\%s" % rule_file, "r").read().splitlines()
        for i in range(0, len(rule_lines)):
            if not " - " in rule_lines[i] and rule_lines[i].endswith(":"):
                print "Loading section: %s" % rule_lines[i].replace(":", "")
            elif ' - ' in rule_lines[i]:
                rbl_domain = rule_lines[i].split(' - ')[1]
                rules[ruleName].append(rbl_domain)
                dns_zones.append(rbl_domain)
        print "Loaded %d for '%s'" % (len(rules[ruleName]), ruleName)


def WriteLine(file, line):
    written = 0
    while not written:
        try:
            out = open(file, "a")
            out.write("%s\n" % line)
            out.close()
            written = 1
        except:
            continue


if __name__ == "__main__":
    options = optparse.OptionParser()
    options.add_option("--iprange", dest="iprange", type="string", default="")
    options.add_option("--threads", dest="threads", type="int", default=1)
    (opts, args) = options.parse_args()

    try:
        useragents = open("UserAgents.txt", "r").read().splitlines()
    except:
        useragents = ["Mozilla/5.0 (Windows NT 6.1; WOW64; rv:16.0) Gecko/20100101 Firefox/16.0"]

    if opts.iprange.endswith(".txt"):
        ip_addresses = open(opts.iprange, "r").read().splitlines()
    else:
        try:
            network = ipaddr.IPv4Network(opts.iprange)
        except ValueError:
            print "Invalid ip range/mask"
            sys.exit()

        ip_addresses = [ip.exploded for ip in network.iterhosts()]
        if len(ip_addresses) == 0:
            ip_addresses = [opts.iprange]
    print "IP's to check: %d" % len(ip_addresses)

    dns_zones = []
    rules = {}
    LoadRules()

    threads = []
    for i in range(0, opts.threads):
        thread = Checker(i + 1)
        threads.append(thread)
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print "Finished running"