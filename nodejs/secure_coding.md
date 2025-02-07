# nodejs security coding
```
https://www.stackhawk.com/blog/guide-to-security-in-node-js

https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

https://blog.risingstack.com/node-js-security-checklist/


Third Party Security Packages
https://github.com/lirantal/awesome-nodejs-security

Top Libiraries in NodeJS
https://technostacks.com/blog/nodejs-libraries/

```

# QUERY STRING

|URL		|	Content of request.query.foo in code|
|----------|----------------------------------------
|?foo=bar	|	'bar' (string)					     |
|?foo=bar&foo=baz|	['bar', 'baz'] (array of string)|
|?foo[]=bar	|['bar'] (array of string)|
|?foo[]=bar&foo[]=baz|	['bar', 'baz'] (array of string)|
|?foo[bar]=baz|	{ bar : 'baz' } (object with a key)|
|?foo[]baz=bar|['bar'] (array of string - postfix is lost)|
|?foo[][baz]=bar|	[ { baz: 'bar' } ] (array of object)|
|?foo[bar][baz]=bar	|{ foo: { bar: { baz: 'bar' } } } (object tree)|
|?foo[10]=bar&foo[9]=baz|	[ 'baz', 'bar' ] (array of string - notice order)|
|?foo[toString]=bar	|{} (object where calling toString() will fail)|

## Helmet
```
设置各种 HTTP 响应标头，列表：

https://helmetjs.github.io/

Strict-Transport-Security - HSTS
X-Frame-Options - Clickjacking
X-XSS-Protection - reflected XSS
Content-Security-Policy - XSS & Clickjacking
X-Content-Type-Options - tell the browser not to change MIME types specified in Content-Type header. 
Cache-Control and Pragma - prevent browsers from caching the given responses (pages contain sensitive info)
X-Download-Options - prevents IE browser from executing downloaded files
Expect-CT - Certificate Transparency
```

## Bcrypt & Scrypt
```
密码安全模块

https://www.npmjs.com/package/bcrypt
https://www.npmjs.com/package/scrypt
```

## Validator.js (anti Injections)
```
输入验证模块。它强制要求用户输入符合要求

https://snyk.io/advisor/npm-package/dompurify
https://www.npmjs.com/package/validator
https://snyk.io/advisor/npm-package/xss-filters
https://www.npmjs.com/package/express-mongo-sanitize
```

## ESLint security plugin
```
可帮助在开发过程中识别易受攻击的 Node.js 代码

https://www.npmjs.com/package/eslint-plugin-security
```

## Dependency security check
```
node_module检查

为了package/module 并检查易受攻击的依赖项，您可以使用 Snyk、Node Security Project (NSP) 等工具，或运行 npm-audit 来追踪和修补漏洞。 
```

## 速率限制
```
https://www.npmjs.com/package/svg-captcha
https://www.npmjs.com/package/ratelimiter

expending error timeout
https://libraries.io/npm/express-brute
https://libraries.io/npm/express-bouncer

account locking
https://www.npmjs.com/package/mongoose
```
## sanitize untrusted HTML (XSS)
```
https://github.com/leizongmin/js-xss
```

## escape output (XSS)
```
https://github.com/ESAPI/node-esapi
https://github.com/component/escape-html
```

## logging & monitor event loop
```
https://www.npmjs.com/package/bunyan
https://www.npmjs.com/package/winston
https://www.npmjs.com/package/pino

DDoS - tracing response time
https://snyk.io/advisor/npm-package/toobusy-js
```

## CSURF & CSRF & SameSite Header
```
https://www.npmjs.com/package/csrf
https://www.npmjs.com/package/csurf

const csurf = require('csurf'); 
const csrfProtection = csurf({ cookie: true }); 
app.use(csrfProtection);


const session = require('express-session'); 
app.use(session({ cookie: { sameSite: 'strict' } }));
```

## SQL injection
```
ORM/ODM 库：使用 ORM（对象关系映射）或 ODM（对象文档映射）库，
例如 Sequelize 或 Mongoose，它们本质上都可以处理参数化查询

const { QueryTypes } = require('sequelize');

await sequelize.query(
  'select * from MyTable where id = :p1',
  {
    replacements: { p1: id }, // id 来自于请求参数
    type: QueryTypes.SELECT
  }
);


 

PostgreSQL

https://www.npmjs.com/package/pg
```

## command injection
```
可以通过使用child_process.execFile来解决
```
## HPP
```
https://www.npmjs.com/package/hpp
```

## XXE
```
阻止这种攻击最简单的方法就是禁用第三方库的解析特性。例如 node-libxml 第三方库，就提供了一系列方法来验证文件类型，保护您的应用免受这种攻击
```

## insecure regex
```
https://www.npmjs.com/package/safe-regex
https://github.com/davisjam/vuln-regex-detector
```

## HTTPS
```
Strict-Transport-Security (HSTS)
express-force-https来强制所有传入的请求使用HTTPS
```

## Identification Authentication
```
OAuth 2.0
JWT（JSON Web Tokens）
Passport.js
MFA
SSO

```

## Access control (authorization)
```
https://www.npmjs.com/package/acl
```

## Cookie security
```
Secure - sending cookie on HTTPS only
HttpOnly - prevents the cookie from being accessed by client-side JavaScript (XSS)
SameSite - prevent cookies from being sent in cross-site requests (CSRF)
```

## Block Event Loop
```
https://nodejs.org/en/docs/guides/dont-block-the-event-loop/

Node.js 允许将回调分配给 IO 阻塞事件。这样，主应用程序就不会被阻塞，回调会异步运行。因此，作为一般原则，所有阻塞操作都应异步完成，以便事件循环不会被阻塞。

即使您异步执行阻塞操作，您的应用程序仍可能无法按预期运行。如果回调之外的代码依赖于回调内的代码先运行，就会发生这种情况。例如，考虑以下代码：

const fs = require('fs');
fs.readFile('/file.txt', (err, data) => {
  // perform actions on file content
});
fs.unlinkSync('/file.txt');


unlinkSync函数可能在回调之前运行，这将在对文件内容执行所需操作之前删除文件。这种竞争条件还会影响应用程序的安全性。一个例子是在回调中执行身份验证并且经过身份验证的操作同步运行的场景。为了消除这种竞争条件，您可以将所有相互依赖的操作编写在一个非阻塞函数中。通过这样做，您可以保证所有操作都按正确的顺序执行。例如，上面的代码示例可以以非阻塞方式编写如下：

const fs = require('fs');
fs.readFile('/file.txt', (err, data) => {
  // perform actions on file content
  fs.unlink('/file.txt', (err) => {
    if (err) throw err;
  });
});
在上面的代码中，取消链接文件的调用和其他文件操作都在同一个回调中。这提供了正确的操作顺序。

```

## Error handle
```
https://snyk.io/advisor/npm-package/forever
https://snyk.io/advisor/npm-package/pm2
```

## Request size limitation
```
https://snyk.io/advisor/npm-package/body-parser
https://www.npmjs.com/package/raw-body
```

## Callback hell
```
USE
- flat Promise chain
- async/await
- Promise.promisifyAll()

```

## 使用对象属性描述符 object property descriptor
```
对象属性包含三个隐藏属性：（writable如果为 false，则属性值不可改变）、enumerable（如果为 false，则属性不可在 for 循环中使用）和configurable（如果为 false，则属性不可删除）。通过赋值方式定义对象属性时，这三个隐藏属性默认设置为 true。这些属性可以设置如下：

const o = {};
Object.defineProperty(o, "a", {
    writable: true,
    enumerable: true,
    configurable: true,
    value: "A"
});
除此之外，还有一些针对对象属性的特殊函数。Object.preventExtensions()防止向对象添加新属性。


```

## Prototype Pollution
```
这些属性描述符确实可以帮助增加安全性:

javascriptCopy// 例如可以让原型上的关键属性不可修改
Object.defineProperty(Object.prototype, 'criticalMethod', {
    writable: false,
    configurable: false
});

对防止原型污染更有效的方法是:

javascriptCopy// 冻结整个原型
Object.freeze(Object.prototype);

// 或创建无原型对象
const safeObject = Object.create(null);
建议在处理原型污染问题时，使用专门的验证库(如 joi)或采用更完整的安全策略，而不是仅依赖于这些属性描述符。属性描述符更适合用于设计API和控制对象的行为模式。

```
