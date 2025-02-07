# Tools -- Endpoint / JS link  
```
目的：多收集endpoint，扩大攻击面，增加发现漏洞的机率

https://github.com/bishopfox/jsluice
https://github.com/edoardottt/cariddi
https://github.com/GerbenJavado/LinkFinder
https://github.com/jobertabma/relative-url-extractor
https://github.com/dark-warlord14/JSScanner
https://github.com/hmx222/JScanner
https://github.com/0x240x23elu/JSScanner
https://github.com/zseano/JS-Scan
https://github.com/InitRoot/BurpJSLinkFinder
https://github.com/0xsha/GoLinkFinder
https://github.com/n0mi1k/apk2url
https://github.com/Velocidex/velociraptor
https://github.com/karthikuj/sasori
https://github.com/AtlasWiki/EndPointer
https://github.com/projectdiscovery/urlfinder

https://github.com/tomnomnom/waybackurls
https://github.com/projectdiscovery/katana
https://github.com/hakluke/hakrawler
https://github.com/michenriksen/aquatone
https://github.com/owasp-amass/amass
https://github.com/projectdiscovery/subfinder 
https://github.com/maurosoria/dirsearch
https://github.com/stefanoj3/dirstalk
https://github.com/H4ckForJob/dirmap
https://github.com/stefanoj3/dirstalk
https://github.com/Isona/dirble
https://github.com/tomnomnom/unfurl

path wordlist
https://github.com/M0ge/dirsearch_dicc
https://github.com/0xPugal/fuzz4bounty
https://github.com/cujanovic/dirsearch-wordlist
https://github.com/Bo0oM/fuzz.txt


find parameters
https://github.com/1hehaq/recx    
https://github.com/ffuf/ffuf 
```
---

# Tools -- SCA/SAST

>目的：发现更多候选漏洞

### nodejs security scanner
https://geekflare.com/nodejs-security-scanner/

### Synk
https://www.npmjs.com/package/snyk

### Node-Secure-CLI
https://github.com/NodeSecure/cli

### nodejsscan
https://github.com/ajinabraham/NodeJsScan

### Retire.js
https://retirejs.github.io/retire.js/
https://github.com/RetireJS/retire.js

### EsLint
http://jshint.com/
https://www.npmjs.com/package/eslint
https://github.com/eslint-community/eslint-plugin-security

https://medium.com/greenwolf-security/linting-for-bugs-vulnerabilities-49bc75a61c6

### AuditJS
https://github.com/sonatype-nexus-community/auditjs

### npm audit
https://www.npmjs.com/package/npm-audit-html
https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities

### OWASP dependency-check
https://dependencytrack.org/
https://dl.bintray.com/jeremy-long/owasp/dependency-check-5.2.4-release.zip

### Renovate (dependency)
https://renovatebot.com/

### Fortify > 18.20
-

### MegaLinter
https://github.com/oxsecurity/megalinter

### Threat Mapper
https://github.com/deepfence/ThreatMapper

https://medium.com/disruptive-labs/static-analysis-of-client-side-javascript-for-pen-testers-and-bug-bounty-hunters-f1cb1a5d5288

---
# Tools -- Secret Finder
>目的：找硬编码credentials (local / github)
```
https://github.com/m4ll0k/SecretFinder
https://github.com/securing/DumpsterDiver
https://github.com/auth0/repo-supervisor
https://github.com/dxa4481/truffleHog

eslint-plugin-no-secret (hardcode)
https://github.com/nickdeis/eslint-plugin-no-secrets

https://github.com/eth0izzle/shhgit
https://github.com/gitleaks/gitleaks
https://github.com/awslabs/git-secrets
https://github.com/anshumanbh/git-all-secrets
https://github.com/Yelp/detect-secrets
https://github.com/Skyscanner/whispers 
https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning
```

# RegEx
```
find . -path "./dev/.hg/*" -prune -o -path "./dev/node_modules/*" -prune -o -type f -print0 | xargs -0 grep -ie "session\|api\|db\(u\|p\|\-\)\|database\|jwt\|[a-zA-Z]key\|\([a-zA-Z0-9]\)[\-_]key\|password\|passwd\|pass\|pwd\|secret\|token\|login\|user" --color=always | grep -x '.\{,400\}' | less -R
```

---
# Tools -- Others
>目的：反分析 / 反逆向 机制的破解

### UglifyJS解压缩 JavaScript：
```
https://beautifier.io/
https://github.com/beautify-web/js-beautify
https://www.npmjs.com/package/js-beautify
https://pypi.org/project/jsbeautifier/
https://github.com/HookyQR/VSCodeBeautify
```

### 反混淆工具
```
https://github.com/mindedsecurity/JStillery
http://relentless-coding.org/projects/jsdetox
https://github.com/einars/js-beautify
https://github.com/geeksonsecurity/illuminatejs
http://www.jsnice.org/
```
---
# Dangerous Functions Finder
```
RegEx

find ./dev -path "./dev/.hg/*" -prune -o -path "./dev/node_modules/*" -prune -o -type f -print0 | xargs -0 grep -e "\.innerText\b\|\.src\b\|\.text\b\|\.textContent\b\|\.value=\b\|Database\b\|Function\b\|IndexedDB\b\|console\.log\b\|createContextualFragment\b\|document\.URL\.indexOf\b\|document\.URL\.substring\b\|document\.cookie\b\|document\.location\.href\b\|document\.referrer\b\|document\.write\b\|document\.writeln\b\|eval\b\|execScript\b\|history\.pushState\b\|history\.replaceState\b\|innerHTML\b\|insertAdjacentHTML\b\|location\b\|location\.assign\b\|location\.hostname\b\|location\.href\b\|location\.pathname\b\|location\.protocol\b\|location\.replace\b\|location\.search\b\|outerHTML\b\|setImmediate\b\|setInterval\b\|setTimeout\b\|window\.addEventListener\b\|window\.localStorage\b\|window\.name\b\|window\.postMessage\b\|window\.sessionStorage" --color=always | grep -x '.\{,400\}' | less -R
```
