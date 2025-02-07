# GraphQL Security Tools

### 用于测试的 GraphQL endpoints
```
- 支持introspection query:
http://3.138.161.132:4000/graphql	(GET & POST CSRF, alias based batching)
http://3.18.83.48:4000/graphql		(GET & POST CSRF, alias based batching)
http://52.56.70.57:4000/graphql		(alias based batching)
http://138.197.166.42:4000/graphql	(alias & JSON based batching)
```
---
### 完整GraphQL安全工具列表
[GraphQL_Hacking](./graphql_hacking.md)

---
### 工具测试的策略与分类
```
nodejs的graphql由Apollo (graphql-js)实现，prod环境默认禁用introspection query (NODE_ENV =='production')，
 
所以这里对安全工具的能力测试会分为三类：
第一类：假设目标支持introspection，或可以获取到graphql schema，在此基础上对相应可用的工具进行能力测试
第二类：假设introspection query禁用，也无schema，但有field suggestion，在此基础上对相应可用的工具进行能力测试
第三类：假设无法获取schema，并且field suggestion也被屏蔽，纯黑盒工具测试

不同类型工具应用于不同场景。
```
---

### Apollo 特性
[GraphQL-Threat-Apollo](https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/apollo.md?plain=1#security-considerations)

<table>
	<tr>
		<th align="center">Field Suggestions</th>
		<th align="center">Query Depth Limit</th>
		<th align="center">Query Cost Analysis</th>
		<th align="center">Automatic Persisted Queries</th>
		<th align="center">Introspection</th>
		<th align="center">Debug Mode</th>
		<th align="center">Batch Requests</th>
	</tr>
	<tr>
		<td align="center">✅<br>Enabled by Default</td>
		<td align="center">⚠️<br>Disabled by Default (Supported via External Libraries)</td>
		<td align="center">⚠️<br>Disabled by Default (Supported via External Libraries)</td>
		<td align="center">⚠️<br>Disabled by Default</td>
		<td align="center">✅<br>Enabled if NODE_ENV is not set to 'production' </td>
		<td align="center">✅<br>exception.stacktrace exists if NODE_ENV is not set to 'production' or 'test' </td>
		<td align="center">✅<br>Enabled by Default</td>
	</tr>
</table>

Apollo is based on graphql-js which validates the following checks when a query is sent:
[Apollo_request-validations](https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/apollo.md#request-validations)

### 评星规则
```
⭐️⭐️⭐️⭐️⭐️ -- 好用，且非常实用
⭐️⭐️⭐️⭐️   -- 好用，需要时可用
⭐️⭐️⭐️     -- 一般，也许用的到
⭐️⭐️       -- 不行，但可以参考
⭐️	   -- 不行，没啥太大用
❌	   -- 垃圾，浪费时间啊
```
---
## [❗️] 第一类
>基于已有GraphQL schema / 或支持introspection query时，可用的工具

### [ ✅ ] Graphql-voyager - ⭐️⭐️⭐️⭐️
>https://github.com/graphql-kit/graphql-voyager

>https://graphql-kit.com/graphql-voyager/ (online)
```
通过introspection query获取到完整schema之后，对其进行可视化分析，标记出各Object之间的引用关系路径，
对安全来讲，可以对其分析后，找出可以绕过访问控制的其他引用路径
```
---
### [ ✅ ] Graphql-Path-Enum - ⭐️⭐️⭐️
>https://gitlab.com/dee-see/graphql-path-enum/
```
通过introspection query获取到完整schema之后（或由用户提供），用这个工具对其分析找出可以绕过访问控制的其他引用路径，属于辅助分析工具
Rust写的，时间原因没安装环境，直接copy作者的运行demo

$ graphql-path-enum -i ./test_data/h1_introspection.json -t Skill
Found 27 ways to reach the "Skill" node from the "Query" node:
- Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check_response) -> ChecklistCheckResponse (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_checks) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (clusters) -> Cluster (weaknesses) -> Weakness (critical_reports) -> TeamMemberGroupConnection (edges) -> TeamMemberGroupEdge (node) -> TeamMemberGroup (team_members) -> TeamMember (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (embedded_submission_form) -> EmbeddedSubmissionForm (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_program) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_programs) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listing) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listings) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (me) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentest) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentests) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (skills) -> Skill
- Query (report) -> Report (bounties) -> Bounty (invitations) -> InvitationsClaimBounty (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (report_retest_user) -> ReportRetestUser (invitation) -> InvitationsRetest (report) -> Report (bounties) -> Bounty (invitations) -> InvitationsClaimBounty (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (reports) -> TeamMemberGroupConnection (edges) -> TeamMemberGroupEdge (node) -> TeamMemberGroup (team_members) -> TeamMember (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (skills) -> Skill
- Query (sla_statuses) -> SlaStatus (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (triage_inbox_items) -> TriageInboxItem (report) -> Report (bounties) -> Bounty (invitations) -> InvitationsClaimBounty (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (users) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (weaknesses) -> Weakness (critical_reports) -> TeamMemberGroupConnection (edges) -> TeamMemberGroupEdge (node) -> TeamMemberGroup (team_members) -> TeamMember (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (webhook) -> Webhook (created_by) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill

```
---
### [ ✅ ] graphqler - ❌
>https://github.com/sorokinpf/graphqler
```
代码很多BUG，基于introspection结果来找出一些特定的type，没啥大用

elementary: issue all elementary queries
all_args: find all types with fields with parameters and issue query for each
loops: find defined number of loops and issue query for each
alt_path: find all pathes to given type
single_query: issue single query
```
---
### [ ✅ ] graphicator - ⭐️⭐️⭐️
>https://github.com/cybervelia/graphicator
```
向目标发送introspection query，获取结果后，根据参数名的含义，尝试猜测有效参数值，以构建真实请求
成功率不太高，这种事情让LLM做应该会比较好，software 1.0写太死就不行。

(venv) labs :: hacktools/graphql/graphicator » python graphicator.py --insecure --multi --target "http://52.56.70.57:4000/graphql" --header "Content-Type:application/json" --verbose --no-cache

  _____                  __    _             __
 / ___/____ ___ _ ___   / /   (_)____ ___ _ / /_ ___   ____
/ (_ // __// _ `// _ \ / _ \ / // __// _ `// __// _ \ / __/
\___//_/   \_,_// .__//_//_//_/ \__/ \_,_/ \__/ \___//_/
               /_/

By @fand0mas

[-] Targets:  1
[-] Headers:  'Content-Type', 'User-Agent'
[-] Verbose
[-] Using cache: False
************************************************************
  0%|                         | 0/1 [00:00<?, ?it/s][*] Enumerating... http://52.56.70.57:4000/graphql
[*] Retrieving... => query {ping String }
[*] Retrieving... => query {getItem  { id,data } }
[*] Retrieving... => query {companiesWithRelationships  { pageInfo { hasNextPage,hasPreviousPage,startCursor,endCursor },totalCount } }
[*] Retrieving... => query {company  { id,type,name,domain,claimed,hqLocation,website,bio,primaryCategory,solutionTypes,linkedInProfile,logoUrl,bannerUrl,salesEmailAddress,employeesGlobally,employeesUK,revenueWorldwide,revenueUK,financialYearEnd,mspOption,licensingModelOption,customerProfile,customerProfileVerticals,linkToResources,vendorIntegrations,noPartnersInUK,targetNumberOfPartnersUK,existingPartnerUrls,estimatedRevenueSalesWithPartners,createdAt,updatedAt,inHouseSupportOffering,solutionsOffered,expectedYear1Margin,expectedYear1Revenue,partnerVendors,averageSalesCycle,averageSmbDealSize,averageEnterpriseDealSize,averagePartnerMargin } }
[*] Retrieving... => query {companies  { pageInfo { hasNextPage,hasPreviousPage,startCursor,endCursor },totalCount } }
[*] Retrieving... => query {companyWithRelationships  { company { id,type,name,domain,claimed,hqLocation,website,bio,primaryCategory,solutionTypes,linkedInProfile,logoUrl,bannerUrl,salesEmailAddress,employeesGlobally,employeesUK,revenueWorldwide,revenueUK,financialYearEnd,mspOption,licensingModelOption,customerProfile,customerProfileVerticals,linkToResources,vendorIntegrations,noPartnersInUK,targetNumberOfPartnersUK,existingPartnerUrls,estimatedRevenueSalesWithPartners,createdAt,updatedAt,inHouseSupportOffering,solutionsOffered,expectedYear1Margin,expectedYear1Revenue,partnerVendors,averageSalesCycle,averageSmbDealSize,averageEnterpriseDealSize,averagePartnerMargin },mutualCustomerCount,theirProspectsOurCustomersCount,theirCustomersOurProspectsCount,overlappingVendors } }
... ignore more output ...

(venv) labs :: hacktools/graphql/graphicator » cat reqcache/d99470e93460908b345326c0a28e58fc444ba4b2.json
{
    "data": {
        "companies": {
            "pageInfo": {
                "hasNextPage": false,
                "hasPreviousPage": false,
                "startCursor": "eyJpZCI6IjIxZmUwMTlmLTVmMzUtNGYzZC1hNWExLWUwNmNjMWViYjVjYiJ9",
                "endCursor": "eyJpZCI6Ijk4NjQxYzllLWVjY2UtNGU4Ny04ZDA0LTI1NDE5ZGI3NTljOSJ9"
            },
            "totalCount": 66
        }
    }
}
```

---
### [ ✅ ] GraphCrawler - ❌
>https://github.com/gsmith257-cyber/GraphCrawler
```
首先，这个工具需要schema文件或目标开启introspection，如果没有，他会调用另一个工具clairvoyance来爆破queries (也在本列表有测试)
拿到schema之后，本工具load进来，分析一下可能敏感的query或mutation，然后会问你是否需要分析引用路径，再调用graphql-path-enum去分析 (也在本列表有测试)
所以这个看起来炫酷的工具实际上什么也没做。
```
<img width="1287" alt="image" src="https://github.com/user-attachments/assets/7fe82634-871a-4e17-8371-5fbd07971c1c" />
<img width="1541" alt="image" src="https://github.com/user-attachments/assets/e231fef4-634d-43f3-84f7-3808a467bc39" />

---
### [ ✅ ] GraphQLmap - ⭐️⭐️⭐️
>https://github.com/swisskyrepo/GraphQLmap
```
这个工具作者也是SSRFmap的作者，该工具主要用于SQL/NoSQL injection的检测
该工具是先利用-u参数连接已经确认的Graphql endpoint，进入交互模式，然后通过introspection来dump出schema
再选择需要检测的数据库SQL注入类型，包括mysqli, mssqli, postgresqli, and nosqli
```
![image](https://github.com/user-attachments/assets/dc716bff-8b61-4412-bd5e-ac3f7d0aa58b)
![image](https://github.com/user-attachments/assets/95d083fb-cc09-4807-aa50-86f89391c426)

---
### [ ✅ ] ShapeShifter - ⭐️
>https://github.com/szski/shapeshifter
```
introspection query的结果提取出query并测试是否可以执行，没啥大用
```
![image](https://github.com/user-attachments/assets/484a89b2-e6a0-4ab1-b87f-dae84b0844c6)

---
### [ ✅ ] GQLSpection - ⭐️
>https://github.com/doyensec/GQLSpection
```
解析introspection的结果，生成所有query和mutation，没啥大用，这功能很多工具都可以做
```
![image](https://github.com/user-attachments/assets/5ee9af40-f2d7-47e4-83a1-21497cddd473)

---
### [ ✅ ] InQL - ⭐️⭐️⭐️⭐️
>https://github.com/doyensec/inql
```
Burp插件，很流行，基于introspection的结果来构建所有的query、mutation等
Attacker模块支持对变量进行 Brute Force & Injection

被测变量占位符：
    $[INT:first:last] - 整数爆破
    $[FILE:path:first:last] - 挂字典文件
```
<img width="907" alt="image" src="https://github.com/user-attachments/assets/d9b9fea8-54e0-4621-9260-5810d854d6ee" />
<img width="906" alt="image" src="https://github.com/user-attachments/assets/8ccb158a-cbd3-4508-950d-c8206e2588a2" />


---
## [❗️] 第二类
>无schema / 或禁用introspection，但有field suggestion，可用的工具
---


### [ ✅ ] clairvoyance - ⭐️⭐️⭐️⭐️
>https://github.com/nikitastupin/clairvoyance

>dict: https://github.com/Escape-Technologies/graphql-wordlist/blob/main/wordlists/queryFieldWordlist.txt

```
当introspection query禁用时，挂字典纯黑盒爆破Fields的工具，但依赖field suggestion，字典的好坏起决定性因素，可以生成和schema一样格式的json文件
效果还是不错的，我没挂字典用他自带的也能跑出一部分fields，queryFieldWordlist太大，导致凯峰服务器断开链接了，但我本地grep看了一下，
字典里面包含的关键字完全可以覆盖目标endpoint 所有的fields，最后直接用凯峰定义的文档生成了一个字典，query都跑出来了

./clairvoyance  http://110.84.211.230:7002/graphql -c 10 -k -m 3 -p slow -v -o xx.json -w ~/hacktools/wordlist/graphql-wordlist/wordlists/queryFieldWordlist.txt
```
![img_v3_02ij_3046e90e-b72c-4283-a42e-80163a7e3a6g](https://github.com/user-attachments/assets/5b6d7ea1-4d62-4606-a846-46ac1c8d7872)
<img width="302" alt="image" src="https://github.com/user-attachments/assets/1ca69128-d810-4cc6-8bdd-a80082030260" />

---

---
## [❗️] 第三类
>schema & suggestion 都无，纯黑盒工具

### [ ✅ ] graphw00f - ⭐️⭐️⭐️⭐️
>https://github.com/dolevf/graphw00f
```
用于发现测试目标的graphql端点，并可以对目标graphql引擎进行指纹识别，
支持自定义UA，Proxy，Header，爆破字典

labs :: hacktools/graphql/graphw00f » python main.py -H "Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MzY5MTEyMjcsImRhdGEiOnsidXNlciI6eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9fSwiZXhwIjoxNzM2OTk3NjI3fQ.eEJzAat6gDkzcJDnOl5Y5W31hRveuUr6QaJAmFelkYk" -d -f -t "http://110.84.211.230:7002/"
                +-------------------+
                |     graphw00f     |
                +-------------------+
[*] Checking http://110.84.211.230:7002//
[*] Checking http://110.84.211.230:7002//graphql
[!] Found GraphQL at http://110.84.211.230:7002//graphql
[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Apollo)
[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/apollo.md
[!] Technologies: JavaScript, Node.js, TypeScript
[!] Homepage: https://www.apollographql.com
[*] Completed.
```
---
### [ ✅ ] graphql-cop - ⭐️⭐️⭐️⭐️⭐️
>https://github.com/dolevf/graphql-cop
```
黑盒扫描 Graphql endpoint 各种漏洞, 可以自定义Header，可使用HTTP/TOR proxy
以Json格式输出会带有curl格式的POC
```
<img width="1338" alt="image" src="https://github.com/user-attachments/assets/a83cfae0-eac1-486d-bac2-ec50a402c6ac" />

---
### [ ✅ ] qevlar - ⭐️⭐️
>https://github.com/oslabs-beta/qevlar
```
对endpoint进行可配置的黑盒扫描, show一个测试类型菜单给选择，主要测试query速率限制、深度以及SQL/NoSQL
交互方式不好，有BUG，结果不准确；但是生成POC的代码/paylaod 可以参考。

><><><><><>< W E L C O M E  T O  Q E V L A R ><><><><><><


Available Tests:
═══════════════════════════════
0 : Generate Config
1 : Rate Limit Test
2 : Adaptive Rate Limiting Test
3 : Fixed Depth Test
4 : Incremental Depth Test
5 : Field Duplication Test
6 : Query Batch Test
7 : SQL Malicious Injection Test
8 : NoSQL Malicious Injection Test
9 : Cross-Site Scripting Injection Test
10 : OS Command Injection Test
Q: Exit qevlar testing library
═══════════════════════════════

Enter the number of the test to run or Q to quit:
```
---
### [ ✅ ] CrackQL - ⭐️⭐️⭐️⭐️⭐️
>https://github.com/nicholasaleks/CrackQL

>https://www.kitploit.com/2022/07/crackql-graphql-password-brute-force.html

```
利用Graphql batch query的特性，把大量query塞到一个request里，绕过速率限制对各种功能点发起brute攻击，
另外也可以向被fuzz参数发一些常见SQLi and XSS payloads，看字典怎么写

===> 使用中重要的几个参数：
-q 要攻击的目标query，这个需要提前抓取，保存为 .graphql 文件，里面用 |str |int |float 来标记被注入替换的参数
-i 事先生成的csv字典文件，根据目标query情况自己生成，例如user:pass对，OTP的6位数字，或是UUID等
-b 定义每个request中query数量，默认100个（Number of batch operations per GraphQL document）
-D 每个request之间的延时，例如有些速率限制1分钟，就可以延时60秒发一个request


===> 支持的攻击类型 与 graphql query文件samples

### Password Spraying Brute-forcing
/login.graphql

mutation {
  login(username: {{username|str}}, password: {{password|str}}) {
    accessToken
  }
}

### MFA OTP Bypass
/otp-bypass.graphql

mutation {
  twoFactor(otp: {{otp|int}}) {
    accessToken
  }
}

### User Account Enumeration
/enumeration.graphql

query {
  signup(email: {{email|str}}, password: {{password|str}}) {
    user {
      email
    }
  }
}

### Insecure Direct Object Reference (IDOR/BOLA)
/idor.graphql

query {
  profile(uuid: {{uuid|int}}) {
    name
    email
    picture
  }
}

```
---
### [ ✅ ] graphinder - ❌
>https://github.com/Escape-Technologies/graphinder
```
安装很久，还有BUG，不好用
```
---
### [ ✅ ] batchQL - ⭐️⭐️⭐️⭐️
>https://github.com/assetnote/batchql
```
该工具支持检测：

Introspection query 是否启用
Schema suggestions 是否启用
潜在的 GET & POST CSRF 
基于alias的 batching query 是否支持
基于JSON 列表的 batching query 是否支持

功能其实已经被CrackQL 覆盖到了，利用batching query对某个特定的query爆破的命令如下：

python batch.py --query target.txt --wordlist passwords.txt -v '{"loginInput":{"email":"admin@x.com","password":"#VARIABLE#","rememberMe":false}}' --size 100 -e http://target.com/graphiql -p localhost:8080

保存被测试query的文件		--query target.txt.
挂一个字典文件			--wordlist passwords.txt
#VARIABLE# 是被测试参数的占位符	-v {"loginInput":{"email":"admin@example.com","password":"#VARIABLE#","rememberMe":false}}
设定每个request包含多少个query	--size 100
目标graphql 端点			-e http://re.local:5000/graphiql
指定代理				-p localhost:8080

```
<img width="1070" alt="image" src="https://github.com/user-attachments/assets/2955d4b9-8db7-42e3-a347-d7954011d143" />

<img width="905" alt="image" src="https://github.com/user-attachments/assets/b307e97a-dc65-48d0-bf97-3e2358f783c6" />

---
### [ ✅ ] janusQL - ⭐️
>https://github.com/oslabs-beta/janusQL
```
通过显示查询的响应时间、状态代码、开销、吞吐量和负载能力来测试其 GraphQL API 的性能，以及是否受到 DDOS 攻击的保护。
用处不大
```
---
### [ ✅ ] GraphQuail - ❓
>https://github.com/forcesunseen/graphquail
```
Burp插件，测不了，我的破解版Burp只能安装Burp App Store里有的，不在里面的一律加载不了
```
---
### [ ✅ ] GraphQL Raider - ⭐️⭐️⭐️⭐️
>https://github.com/michcheng/GraphQL-Raider
```
Burp插件，选中graphql的request时，会把query进行提取、美化、标记出可以注入的变量
在手动分析的时候，可用
```
<img width="663" alt="image" src="https://github.com/user-attachments/assets/da2159bd-f20f-482e-929a-078f5e01b1e0" />
<img width="662" alt="image" src="https://github.com/user-attachments/assets/5a4f752c-1f6c-4c79-9755-c41ff5f8ea6a" />

---
