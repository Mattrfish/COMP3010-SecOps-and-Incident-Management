## AI Questions

 ### Question 1,2 + 3
* **How to exclude an event in spl query?** "Either != or NOT or Where count != 100"
* **Give me an example of different keyword search queries using SPL. "**Basic: "Index=botsv3 frothly" Phrases: "Index=botsv3 'access denied'" Wildcards: "Index=botsv3 fail\*" "
* **can you explain gacrux.i please as the host name for the web servers. I cant find that the web servers are officially defined as web servers.** 

"In the Frothly environment, gacrux is the naming convention for the fleet of Linux Web Servers. The Name: "Gacrux" is the third-brightest star in the Southern Cross. Frothly uses a celestial naming scheme (e.g., Matar is the mail server, Mars is a server, Hoth is a domain controller). The Suffix (.i-xxxx): The .i-0920... part represents the AWS EC2 Instance ID. Because these servers are in an Auto Scaling Group, they spin up and down automatically, appending their unique AWS ID to the hostname gacrux."

### Quesion 4,5 + 6
* **What is relevance of a SOC understanding the names of buckets when checking if they are secure?**

"The bucket name often indicates the sensitivity of the data. A bucket named frothlywebcode implies source code (Intellectual Property risk), whereas a bucket named frothly-payroll would imply PII (Regulatory/GDPR risk). Knowing the specific bucket name allows analysts to search Pastebin or Dark Web forums to see if the exposed URL is being actively shared by attackers."

### Question 7
* **Would an AWS upload of a txt file be a POST request?**
"It is a great question because the answer is "Usually PUT, but sometimes POST.""

### Question 8
* **What does FQDN mean?"**
FQDN stands for Fully Qualified Domain Name.

It is the complete, absolute address of a specific computer or host on the internet or a private network. It leaves no ambiguity about which machine you are talking about.


## General Questions + Notes/Reminders
 ### Question 1,2 + 3
* Not sure how to find the full mfa path. Could use wildcard for mfa to reduce noise and use != to exclude ConsoleLogin - should be able to find the full json path for mfa this way?
* Remember to use the fields tab to help with queries - could look through the sourcetype to see if there's anything related to hardware? Could it just be called hardware?
* Found that sourcetype=hardware does exsit.
* Hardware sourcetype shows the list hardware for the web servers, however What is gacrux.i? Its not clear that it is a web server, cant seem to find it officially defined anywhere.
* Most likely just a name used for asset management to easily identify the servers? - Correct and it is an ec2 instance. Just need to find the web traffic they are serving to be sure.
* Quick search found that using "access\_combined in Splunk refers to a pre-trained source type for NCSA combined HTTP web server logs" - if i search in the sourcetype it should prove whether it is a web server. 
* Shows loads of successful GET requests from an elastic load balance health check to see if its ready to serve web traffic - proves its a web server as if it goes down then the ELB can stop sending it traffic. 

### Question 4,5 + 6
* PutBucketAcl for tracking s3 Bucket permissions but how to find the permission for everyone to access? Could check the side fields panel - full json acl granted path with a uri. Following it through gives a uri link for "all users" so it must be this. Returns back the one event with the bucket set to "all users". Defo useful command for monitoring buckets permissions.
* Within the json it should give me a username for the user that set it as public and the name of the bucket itself

### Question 7
* finding the txt file - could use a *txt wildcard to search specifcally for txt files, however there could be many txt files on there. Also need to find that it was uploaded rather than downloaded which i assume is a POST request? Turns out to be a PUT which i will use alongside the txt wildcard. (Turns out i can use it wtih method= instead of a wildcard)
* The uploaded txt file could indicate a gray hat scanning for vulnerabilities to report or it could just be someone who stumbled across it and thought they should let them know its open. Couldve been a lot more serious. 

### Question 8
* What does FQDN stand for? Fully Qualified Domain Name  - hostname + domain name
* Ive got the OS outlier (hostname) but how do i found the domain name as it doesnt appear under the hostname? some reasearhc and searching through logs found that it should be under "computername="
*