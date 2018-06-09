# should-i-trust
![](https://img.shields.io/github/stars/ericalexanderorg/should-i-trust.svg) 
![](https://img.shields.io/github/forks/ericalexanderorg/should-i-trust.svg) 
![](https://img.shields.io/github/tag/ericalexanderorg/should-i-trust.svg) 
![](https://img.shields.io/github/release/ericalexanderorg/should-i-trust.svg) 
![](https://img.shields.io/github/issues/ericalexanderorg/should-i-trust.svg) 

## Summary
-------------
should-i-trust is a tool to evaluate OSINT signals for a domain. 

### Use Case
-------------
You're part of a review board that's responsible for evaluating new vendors. You're specifically responsible for 
ensuring new vendors meet compliance and security requirements. 

Standard operation procedure is to ask for one or all of the following: SOC report, VSAQ, CAIQ, SIG/SIG-Lite. All 
vendors will not have these reports and/or questionnaire answers. Maybe it's org process to deny vendor intake
without this information, or maybe, this is a "special" engagement and you need to ascertain trustworthyness without 
the docs. Maybe you don't trust the response in the docs. 

should-i-trust is a tool to go beyond standard responses and look for signals that the organization should not be
trusted. Maybe they're exposing their CI/CD to the internet with no auth. Maybe they have an EC2 instance with prod
code running and no directory restrictions. 

should-i-trust doesn't provide all the information you will need to make a go/no-go decision but it will allow you
to quickly gather OSINT data for further evaluation. 

### Setup
-------------
Create a settings.json file in the python2 file with your cenys.io creds. See settings.json.example for an example. 

### Running
-------------
> python v1.py -d ericalexander.org

The script will prompt for the following
+ Check SSL Labs grade for each cert found
+ Pull data on censys.io findings if results exceed 50. This is to avoid maxing out the free API limitations. 

### Output
-------------
The script will create a working directory with *some* of the API responses. Some respones are saved to reduce API calls on 
future runs to avoid API caps and improve speed. 

The following information will be returned to the console
+ If there's an indicator the domain participates in a bug bounty program
+ Certs found through Google's transparency report
+ SSL Labs grade of sites found (if chosen to run)
+ Censys.io listing of open ports and website titles found
+ Matching repositories found on GitHub, GitLab, and Bitbucket
