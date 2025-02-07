# Web API security testing tools

```
https://www.soapui.org/tools/readyapi/

https://www.soapui.org/tools/soapui/

https://github.com/imperva/automatic-api-attack-tool (依赖API定义规范的漏洞扫描，例如 swaggerPetStore.json)

https://github.com/abunuwas/fencer  (OpenAPI based security testing)

https://github.com/brinhosa/apidetector (Swagger endpoints Scanner)

https://danaepp.com/finding-hidden-api-endpoints-using-path-prediction

https://github.com/BishopFox/sj  (auditing endpoints defined in exposed (Swagger/OpenAPI) definition files.)

https://github.com/assetnote/kiterunner  (多种API类型的API 发现和路由枚举)

https://github.com/ngalongc/openapi_security_scanner  (基于OpenAPI yaml file扫BOLA/IDOR)

https://github.com/Endava/cats  (REST API Fuzzer & testing, 看着可以)

https://github.com/openclarity/apiclarity  (对各种API网关抓的流量进行测试)

https://bbva.github.io/apicheck/  (多个API测试工具的集成工具包)



https://www.zaproxy.org/    (Checkmarx ZAP, 和burp类似)

https://github.com/flipkart-incubator/Astra  (RESTful API安全测试，优秀)

https://github.com/API-Security/APIKit  (端点发现、扫描、审计各种API)

https://github.com/dwisiswant0/wadl-dumper  (Dump all available paths and/or endpoints on WADL file.)

https://github.com/NetSPI/Wsdler (Burp插件，wsdl解析)

https://github.com/portswigger/wsdl-wizard  (Burp插件，发现wsdl)

https://github.com/RhinoSecurityLabs/Swagger-EZ  (基于OpenAPI definitions的API测试

https://github.com/amalmurali47/swagroutes   （从Swagger文件提取API URL)




https://graphql.security/  (Online, 测试了不好用)

https://github.com/szski/shapeshifter  (GraphQL security testing tool)

https://astexplorer.net/   (ASR explorer)

https://graphql-kit.com/graphql-voyager/ (GraphQL introspection 图形化, 列出引用关系路径)

https://github.com/graphql/graphql-playground (IDE)

https://learning.postman.com/docs/sending-requests/graphql/graphql-client-interface/ (Postman)

https://github.com/nikitastupin/clairvoyance （typename enum via wordlist & error message）

https://github.com/swisskyrepo/GraphQLmap    (Can be used as a CLI client also to automate attacks)

https://github.com/oslabs-beta/janusQL  (DoS测试)

https://github.com/oslabs-beta/qevlar （扫描器）

https://github.com/sorokinpf/graphqler (自动化测试)
Talk: https://clck.ru/KDZB3

https://github.com/nicholasaleks/graphql-threat-matrix (不同实现对GraphQL特性的支持)

https://github.com/gsmith257-cyber/GraphCrawler  (用于抓取schema并搜索敏感数据、测试授权、暴力破解模式以及查找给定类型的路径的工具包)

https://gitlab.com/dee-see/graphql-path-enum    (可以列出一个schema中 到达给定type的不同方法)

https://github.com/assetnote/batchql    (GraphQL 安全审计脚本， 主要检测 batch queries 和 mutations.)

https://github.com/dolevf/graphql-cop  （测试 graphql 端点的常见错误配置）

https://github.com/dolevf/graphw00f     (检测服务器中使用了哪种 GraphQL 引擎)

https://github.com/forcesunseen/graphquail (Burp Extension, 根据错误提示推测schema info, 检测DoS)
参考：https://forcesunseen.com/blog/graphql-security-testing-without-a-schema

https://blog.doyensec.com/2020/03/26/graphql-scanner.html    (client and Burp extension.)

https://github.com/doyensec/inql  (Burp扩展，可以分析GraphQL端点或本地自省模式文件。
它会自动生成所有可能的query和mutations，并将它们组织成结构化的视图以供分析,
attacker组件可以让你运行批量GraphQL攻击，这对于规避糟糕的速率限制非常有用。)

https://github.com/doyensec/GQLSpection     (InQL的命令行版本)





https://github.com/Fuzzapi/API-fuzzer  (对RESTful API扫描多种漏洞)
https://github.com/Fuzzapi/fuzzapi  (UI edition)

https://github.com/KissPeter/APIFuzzer  (Fuzz test your application using your OpenAPI or Swagger API definition)

https://github.com/Teebytes/TnT-Fuzzer  (OpenAPI 2.0 (Swagger) fuzzer)

https://github.com/microsoft/restler-fuzzer  (REST API fuzzing tool f)

https://github.com/s0md3v/Arjun  (fuzz parameter)








```

# API Wordlists:

```
API endpoints & objects - 3203 common API endpoints and objects designed for fuzzing.
https://gist.github.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d

https://github.com/chrislockard/api_wordlist

https://github.com/fuzzdb-project/fuzzdb/blob/master/discovery/common-methods/common-methods.txt

API HTTP Request Methods - HTTP requests methods wordlist from SecLists
https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/http-request-methods.txt

API Routes wordlist - AssesNote’s collection of API routes
https://github.com/assetnote/wordlists/blob/master/data/automated.json

api_wordlist - SecList’s collection of API names used for fuzzing web application APIs.
https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/api

Common API endpoints - SecList’s collection of API endpoints
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt

GraphQL wordlist - SecList’s collection of GraphQL endpoints
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/graphql.txt

Hacking-API wordlists - hAPI Hacker’s collection of API paths and wordlists
https://github.com/hAPI-hacker/Hacking-APIs

Kiterunner wordlist - AssestNote’s collection of API wordlists for Kiterunner
https://github.com/assetnote/wordlists/blob/master/data/kiterunner.json

Swagger / OpenAPI wordlist - SecList’s collection of wordlists for finding API docs
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/swagger.txt

Bug Bounty Wordlists - A collection of wordlist good for bug bounties
https://github.com/Karanxa/Bug-Bounty-Wordlists

graphql-wordlist
https://github.com/Escape-Technologies/graphql-wordlist
```

---


# API Pentest Online Books

```

API Pentest Book - API penetration testing notes
https://pentestbook.six2dez.com/enumeration/webservices/apis

API Security Empire - Aims to present unique attack & defense methods in the API Security field
https://github.com/cyprosecurity/API-SecurityEmpire

GraphQL Pentesting - HackTrick’s online book for hacking GraphQL  (⭐️⭐️⭐️⭐️⭐️)
https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html

Web API Pentesting - HackTrick’s online book for hacking web APIs
https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/web-api-pentesting.html
```

---

# Cheatsheets & Checklists
```
MindMap
https://dsopas.github.io/MindAPI/play/

API Security Top 10
https://danaepp.com/apisecuritytop10

GraphQL
https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

Injection Prevention
https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

JSON Web Token (JWT) Security
https://assets.pentesterlab.com/jwt_security_cheatsheet/jwt_security_cheatsheet.pdf

Microservices Security
https://cheatsheetseries.owasp.org/cheatsheets/Microservices_security.html

REST Assessment
https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html

REST Security
https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html

API Penetration Testing
https://apimike.com/api-penetration-testing-checklist

API Testing
https://hackanythingfor.blogspot.com/2020/07/api-testing-checklist.html

API Security Testing
https://github.com/shieldfy/API-Security-Checklist

API security checklist
https://static.wallarm.com/wallarm-webflow/resources/api-security-checklist/API%20Security%20checklist.pdf

https://gitlab.com/pentest-tools/API-Security-Checklist/-/blob/master/README.md
```

---

# API Hacking Articles

```
Graphql-Hacking  (⭐️⭐️⭐️⭐️⭐️)
https://lab.wallarm.com/securing-and-attacking-graphql-part-1-overview/
https://lab.wallarm.com/what/why-and-how-to-disable-introspection-query-for-graphql-apis/
https://lab.wallarm.com/graphql-batching-attack/

Graphql-authentication-bypass  (⭐️⭐️⭐️⭐️⭐️)
https://www.hackerone.com/vulnerability-management/graphql-authentication-bypass

Batching-client-graphql-queries  (⭐️⭐️⭐️⭐️⭐️)
https://www.apollographql.com/blog/batching-client-graphql-queries

GraphQL CSRF
https://blog.doyensec.com/2021/05/20/graphql-csrf.html

https://blog.securelayer7.net/api-penetration-testing-with-owasp-2017-test-cases/
https://blog.forcesunseen.com/graphql-security-testing-without-a-schema
https://escape.tech/blog/graphql-security-wordlist/
https://www.assetnote.io/resources/research/exploiting-graphql


Graphql-query-authentication-bypass-vuln  (ERR_CONNECTION_RESET)
https://s1n1st3r.gitbook.io/theb10g/graphql-query-authentication-bypass-vuln

The Beginner's Guide to API Hacking
https://danaepp.com/beginners-guide-to-api-hacking

API and microservice security
https://portswigger.net/burp/vulnerability-scanner/api-security-testing/guide-to-api-microservice-security

Finding and Exploiting Unintended Functionality in Main Web App APIs
https://bendtheory.medium.com/finding-and-exploiting-unintended-functionality-in-main-web-app-apis-6eca3ef000af

How To Hack API In 60 Minutes With Open Source Tools
https://www.wallarm.com/what/how-to-hack-api-in-60-minutes-with-open-source

How to Hack APIs in 2021
https://labs.detectify.com/2021/08/10/how-to-hack-apis-in-2021/

How to Hack an API and Get Away with It
https://smartbear.com/blog/api-security-testing-how-to-hack-an-api-part-1/

How to Detect the Programming Language of an API
https://danaepp.com/how-to-detect-the-programming-language-of-an-api

How to exploit GraphQL endpoint: introspection, query, mutations & tools
https://www.yeswehack.com/learn-bug-bounty/how-exploit-graphql-endpoint-bug-bounty

Notes from Hacking APIs from Bug Bounty Bootcamp
https://attacker-codeninja.github.io/2021-08-28-Hacking-APIs-notes-from-bug-bounty-bootcamp/

How to craft rogue API docs for a target when they don't exist
https://danaepp.com/how-to-detect-the-programming-language-of-an-api

Sample API Penetration Testing Report
https://underdefense.com/wp-content/uploads/2019/05/Anonymised-API-Penetration-Testing-Report.pdf

Scanning APIs with Burp Scanner
https://portswigger.net/burp/documentation/desktop/scanning/api-scanning

Simplifying API Pentesting With Swagger Files
https://rhinosecuritylabs.com/application-security/simplifying-api-pentesting-swagger-files/

SOAP Security: Top Vulnerabilities and How to Prevent Them
https://brightsec.com/blog/top-7-soap-api-vulnerabilities/

Using Burp to Enumerate a REST API
https://portswigger.net/support/using-burp-to-enumerate-a-rest-api

Exploit APIs with cURL
https://danaepp.com/exploit-apis-with-curl

How to Make Money Hacking APIs
https://danaepp.com/how-to-make-money-hacking-apis

When to give up on an API target
https://danaepp.com/the-bug-bounty-dilemma-when-to-give-up-on-an-api-target

API Fuzzing
https://www.fuzzingbook.org/html/APIFuzzer.html

Finding-hidden-api-endpoints-using-path-prediction
https://danaepp.com/finding-hidden-api-endpoints-using-path-prediction
```

---

# API vulnerability labs

```
APISandbox - Pre-Built Vulnerable Multiple API Scenarios Environments Based on Docker Compose
https://github.com/API-Security/APISandbox

crAPI - Completely ridiculous API (crAPI) will help you to understand the ten most critical API security risks.
https://github.com/OWASP/crAPI

Damn Vulnerable GraphQL App - An intentionally vulnerable implementation of Facebook's GraphQL technology
https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application

DVMS - The Damn Vulnerable Microservice is written in many languages to demonstrate OWASP API Top Security Risks
https://github.com/ne0z/DamnVulnerableMicroServices

DVWS-Node - Damn Vulnerable Web Services is a vulnerable application with a web service and anAPI that can be used to learn about web services/API-related vulnerabilities.
https://github.com/snoopysecurity/dvws-node

Generic University - InsiderPhD’s Laravel demo app that is purposely vulnerable to a number of vulnerabilities on the OWASP API Top 10.
https://github.com/InsiderPhD/Generic-University

VAmPI - VAmPI is a vulnerable API made with Flask and it includes vulnerabilities from the OWASP top 10 vulnerabilities for APIs.
https://github.com/erev0s/VAmPI

vAPI - vAPI is a Vulnerable Adversely Programmed Interface which is Self-Hostable API that mimics OWASP API Top 10 scenarios through Exercises.
https://github.com/roottusk/vapi

vulnerable-graphql-api - A very vulnerable implementation of a GraphQL API.
https://github.com/CarveSystems/vulnerable-graphql-api

WebSheep - WebSheep is an app based on willingly vulnerable ReSTful APIs.
https://github.com/marmicode/websheep
```
