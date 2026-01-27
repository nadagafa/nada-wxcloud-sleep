const path = require("path");
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
//const { init: initDB, Counter } = require("./db");

const logger = morgan("tiny");

const app = express();

const crypto = require('crypto');
const xml2js = require('xml2js');
const bodyParser = require('body-parser');

// 你的微信Token（在微信后台配置的）
const WECHAT_TOKEN = '6tdf';
const ENCODING_AES_KEY = 'LlNqVfyAcLphUjfXkGQYGzhgDtFcJmu87vTIGO6KKIr';
const APP_ID = 'wx2c207bf1e565f67c';

//app.use(express.urlencoded({ extended: false }));
//app.use(express.json());
//app.use(cors());
//app.use(logger);

// 中间件
app.use(bodyParser.text({ type: 'text/xml' }));
app.use(express.json());

// XML解析器
const parser = new xml2js.Parser({
  explicitArray: false,
  ignoreAttrs: true,
  trim: true
});

const builder = new xml2js.Builder({
  cdata: true,
  headless: true,
  rootName: 'xml'
});

// 首页
app.get("/", async (req, res) => {
  // res.sendFile(path.join(__dirname, "index.html"));

 

  console.log('333');
  res.send({
    code: 0,
    data: '111',
  });
});

app.get("/test", async (req, res) => {
  // res.sendFile(path.join(__dirname, "index.html"));

  const test = {

  signature: 'dc4462939328d9010c4f0024502ac2307bab08a9',

  timestamp: '1769499406',

  nonce: '1241093229',

  openid: 'ot-N32xw4DO4KI2koxhBN4QE-rWk',

  encrypt_type: 'aes',

  msg_signature: 'b0cdf60364df23188c58b898f4fecef84a1c266d'

};

const Encrypt = 'G9TJrUC8GFR2g4jXzpGAu24HRrYHZMiGDmu/GqzxggENL1J/yYH74qgP5lEGWOuDWfDlrK+OpLKSjRBCA5/r69irm5sVJ2UMbCZRstKAJDOnkxQKL7bz9jRadBrXXlES/8SWO974I8xmnQe9Z497I6iqBBVk1cGVk5tmpMBAHjzpw7AgvTJCUAIXuii9wiQuZOoEp6iTv23gBltU8Gn5E3gVlTYBZigubSJdUF/mBnQeHdyBMP1fRQJsY6fISaztMIy/ZGj2ukDC7zrpfhRxqCV6RnvCM/O+C58Tr31tSAqk2Rkt26caITe3B6GqpnbkwRHIyjJrJVtNv21OZiV+z0IPNGE6mEDJIu1T4T6xpyfJRBr2QHeB1qim3V263A1cIfu9ar5So+eP18XW+WvBzBjgxKEbjbbpiSl8Bm6Sv2Y=';

  cryptor.verifySignature(test.signature, test.timestamp, test.nonce);

  const decryptedMsg = cryptor.decrypt(Encrypt);
        console.log('解密后的消息:', decryptedMsg);

        // 解析解密后的XML
        const decryptedResult = await parseXML(decryptedMsg);
        const message = decryptedResult.xml;

        res.send({
    code: 0,
    data: message,
  });

  
});

// 获取计数
app.get("/sleep", async (req, res) => {

  const { signature, timestamp, nonce, echostr } = req.query;
  
  // 1. 将token、timestamp、nonce三个参数进行字典序排序
  const arr = [WECHAT_TOKEN, timestamp, nonce].sort();
  
  // 2. 将三个参数字符串拼接成一个字符串
  const str = arr.join('');
  
  // 3. 进行sha1加密
  const sha1 = crypto.createHash('sha1');
  sha1.update(str);
  const result = sha1.digest('hex');
  
  // 4. 将加密后的字符串与signature对比
  if (result === signature) {
    // 验证成功，返回echostr
    console.log('微信验证成功');
    res.send(echostr);
  } else {
    // 验证失败
    console.log('微信验证失败');
    res.status(403).send('验证失败');
  }


  /*
  res.send({
    code: 200,
    data: 'ok'  });
    */
});

// 接收微信客服消息
app.post('/sleep', async (req, res) => {
  try {
    const { signature, timestamp, nonce, encrypt_type, msg_signature } = req.query;
    const xmlBody = req.body;
    
    console.log('POST 消息请求参数:', req.query);
    console.log('POST 消息体:', xmlBody);
    
    // 解析XML
    const result = await parseXML(xmlBody);
    console.log('解析后的XML:', JSON.stringify(result, null, 2));
    
    let message;
    
    // 判断是否是加密消息
    if (encrypt_type === 'aes' || result.xml.Encrypt) {
      // 加密模式
      console.log('检测到加密消息');
      
      // 验证消息签名
      if (!cryptor.verifySignature(signature, timestamp, nonce)) {
        console.log('消息签名验证失败');
        return res.status(403).send('签名验证失败');
      }
      
      // 解密消息
      try {
        const decryptedMsg = cryptor.decrypt(result.xml.Encrypt);
        console.log('解密后的消息:', decryptedMsg);
        
        // 解析解密后的XML
        const decryptedResult = await parseXML(decryptedMsg);
        message = decryptedResult.xml;
      } catch (decryptError) {
        console.error('解密失败:', decryptError);
        return res.status(400).send('解密失败');
      }
    } else {
      // 明文模式
      if (!cryptor.verifySignature(signature, timestamp, nonce)) {
        console.log('明文消息签名验证失败');
        return res.status(403).send('签名验证失败');
      }
      
      message = result.xml;
    }
    
    console.log('处理消息:', JSON.stringify(message, null, 2));
    
    // 处理消息并获取回复
    const replyContent = await handleWechatMessage(message);
    
    // 生成回复
    let responseXml;
    const timestampStr = Math.floor(Date.now() / 1000).toString();
    const nonceStr = Math.random().toString(36).substr(2, 9);
    
    if (replyContent) {
      // 构建回复消息
      const replyMessage = {
        ToUserName: message.FromUserName,
        FromUserName: message.ToUserName,
        CreateTime: timestampStr,
        MsgType: 'text',
        Content: replyContent
      };
      
      const replyXml = builder.buildObject(replyMessage);
      console.log('回复明文XML:', replyXml);
      
      if (encrypt_type === 'aes' || result.xml.Encrypt) {
        // 加密回复
        const encryptedMsg = cryptor.encrypt(replyXml);
        const msgSignature = cryptor.generateSignature(timestampStr, nonceStr, encryptedMsg);
        
        responseXml = builder.buildObject({
          Encrypt: encryptedMsg,
          MsgSignature: msgSignature,
          TimeStamp: timestampStr,
          Nonce: nonceStr
        });
        
        console.log('加密回复XML:', responseXml);
      } else {
        // 明文回复
        responseXml = replyXml;
      }
    } else {
      // 空回复
      responseXml = 'success';
    }
    
    res.set('Content-Type', 'text/xml');
    res.send(responseXml);
    
  } catch (error) {
    console.error('处理消息出错:', error);
    res.status(500).send('服务器错误');
  }
});

// 处理微信消息
async function handleWechatMessage(message) {
  const { MsgType, Content, Event } = message;
  
  console.log(`收到消息类型: ${MsgType}, 事件: ${Event || '无'}`);
  
  switch (MsgType) {
    case 'text':
      return await processTextMessage(Content);
    
    case 'image':
      return '收到图片消息，感谢分享！';
    
    case 'voice':
      const recognition = message.Recognition || '（语音识别未开启）';
      return `语音识别结果：${recognition}`;
    
    case 'video':
    case 'shortvideo':
      return '收到视频消息！';
    
    case 'location':
      return `收到位置信息：${message.Label}`;
    
    case 'link':
      return `收到链接：${message.Title}`;
    
    case 'event':
      return await handleEventMessage(message);
    
    default:
      return '暂不支持此类型消息';
  }
}

// 处理文本消息
async function processTextMessage(content) {
  content = content.trim().toLowerCase();
  
  const keywordMap = {
    '加密': '当前消息已启用加密模式，安全可靠！',
    '明文': '可以切换为明文模式，请在微信后台配置',
    '测试': '加密解密功能测试成功！',
    'help': '支持的命令：\n1. 加密\n2. 测试\n3. help',
  };
  
  if (keywordMap[content]) {
    return keywordMap[content];
  }
  
  return `收到消息："${content}"\n\n当前使用加密传输，安全可靠！`;
}

// 处理事件消息
async function handleEventMessage(message) {
  const { Event, EventKey } = message;
  
  switch (Event) {
    case 'subscribe':
      return '欢迎关注！当前客服系统使用加密通信，保障您的信息安全。';
    
    case 'unsubscribe':
      console.log('用户取消关注');
      return null;
    
    case 'CLICK':
      return `点击菜单：${EventKey}`;
    
    default:
      return '收到事件消息';
  }
}

// 解析XML
async function parseXML(xml) {
  return new Promise((resolve, reject) => {
    parser.parseString(xml, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

// 验证签名函数
function verifySignature(signature, timestamp, nonce) {
  const arr = [WECHAT_TOKEN, timestamp, nonce].sort();
  const str = arr.join('');
  const sha1 = crypto.createHash('sha1');
  sha1.update(str);
  const result = sha1.digest('hex');
  
  return result === signature;
}


// WXBizMsgCrypt 类 - 微信加解密工具
class WXBizMsgCrypt {
  constructor(token, encodingAESKey, appId) {
    this.token = token;
    this.appId = appId;
    
    // AES Key处理
    const aesKey = Buffer.from(encodingAESKey + '=', 'base64');
    if (aesKey.length !== 32) {
      throw new Error('EncodingAESKey 长度无效');
    }
    
    this.key = aesKey;
    this.iv = aesKey.slice(0, 16);
  }

  // 验证签名
  verifySignature(signature, timestamp, nonce, encrypt) {
    const arr = [this.token, timestamp, nonce];
    if (encrypt) arr.push(encrypt);
    
    arr.sort();
    const str = arr.join('');
    const sha1 = crypto.createHash('sha1');
    sha1.update(str);
    const result = sha1.digest('hex');

    console.log('result', result, signature);
    
    return result === signature;
  }

  // 生成回复消息的签名
  generateSignature(timestamp, nonce, encrypt) {
    const arr = [this.token, timestamp, nonce];
    if (encrypt) arr.push(encrypt);
    
    arr.sort();
    const str = arr.join('');
    const sha1 = crypto.createHash('sha1');
    sha1.update(str);
    return sha1.digest('hex');
  }

  // 解密消息
  decrypt(encryptMsg) {
    try {
      // Base64解码
      const encrypted = Buffer.from(encryptMsg, 'base64');
      
      // 创建解密器
      const decipher = crypto.createDecipheriv('aes-256-cbc', this.key, this.iv);
      decipher.setAutoPadding(false);
      
      // 解密
      let decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ]);
      
      // 移除补位
      decrypted = this.decodePKCS7(decrypted);
      
      // 解析消息
      const contentLength = decrypted.readUInt32BE(16);
      const message = decrypted.slice(20, 20 + contentLength).toString('utf8');
      const receiveId = decrypted.slice(20 + contentLength).toString('utf8');
      
      // 验证AppId
      if (receiveId !== this.appId) {
        throw new Error('AppId 不匹配');
      }
      
      return message;
    } catch (error) {
      console.error('解密失败:', error);
      throw new Error('解密失败');
    }
  }

  // 加密消息
  encrypt(replyMsg) {
    try {
      // 生成随机字符串
      const randomStr = this.getRandomStr(16);
      
      // 构造待加密数据
      const msgBuffer = Buffer.from(replyMsg, 'utf8');
      const msgLength = Buffer.alloc(4);
      msgLength.writeUInt32BE(msgBuffer.length, 0);
      
      const data = Buffer.concat([
        Buffer.from(randomStr, 'utf8'),
        msgLength,
        msgBuffer,
        Buffer.from(this.appId, 'utf8')
      ]);
      
      // PKCS7补位
      const paddedData = this.encodePKCS7(data);
      
      // 加密
      const cipher = crypto.createCipheriv('aes-256-cbc', this.key, this.iv);
      cipher.setAutoPadding(false);
      
      const encrypted = Buffer.concat([
        cipher.update(paddedData),
        cipher.final()
      ]);
      
      // Base64编码
      return encrypted.toString('base64');
    } catch (error) {
      console.error('加密失败:', error);
      throw new Error('加密失败');
    }
  }

  // PKCS7编码
  encodePKCS7(buffer) {
    const blockSize = 32;
    const padding = blockSize - (buffer.length % blockSize);
    const paddingBuffer = Buffer.alloc(padding, padding);
    return Buffer.concat([buffer, paddingBuffer]);
  }

  // PKCS7解码
  decodePKCS7(buffer) {
    const padding = buffer[buffer.length - 1];
    if (padding < 1 || padding > 32) {
      return buffer;
    }
    return buffer.slice(0, buffer.length - padding);
  }

  // 生成随机字符串
  getRandomStr(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }
}

// 初始化加密工具
const cryptor = new WXBizMsgCrypt(WECHAT_TOKEN, ENCODING_AES_KEY, APP_ID);

const port = process.env.PORT || 80;

async function bootstrap() {
  //await initDB();
  app.listen(port, () => {
    console.log("启动成功", port);
  });
}

bootstrap();
