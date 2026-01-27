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
    // 1. 验证签名
    const { signature, timestamp, nonce, msg_signature } = req.query;
    if (!verifySignature(signature, timestamp, nonce)) {
      return res.status(403).send('签名验证失败');
    }

    // 2. 解析XML消息
    const xml = req.body;

    console.log('xml:', JSON.stringify(xml));

    const result = await parseXML(xml);
    
    console.log('收到微信消息:', JSON.stringify(result, null, 2));
    
    // 3. 处理不同类型的消息
    const responseXml = await handleWechatMessage(result);
    
    // 4. 返回响应
    if (responseXml) {
      res.set('Content-Type', 'text/xml');
      res.send(responseXml);
    } else {
      res.send('success'); // 空回复
    }
    
  } catch (error) {
    console.error('处理微信消息出错:', error);
    res.status(500).send('服务器错误');
  }
});

// 处理各种类型的微信消息
async function handleWechatMessage(message) {
  const { MsgType, FromUserName, ToUserName } = message;
  
  // 公共返回对象
  const baseResponse = {
    ToUserName: FromUserName,
    FromUserName: ToUserName,
    CreateTime: Math.floor(Date.now() / 1000)
  };
  
  switch (MsgType) {
    
    // 文本消息
    case 'text':
      const content = message.Content;
      console.log('收到文本消息:', content);
      
      // 关键词回复
      const replyText = await processTextMessage(content);
      
      return builder.buildObject({
        ...baseResponse,
        MsgType: 'text',
        Content: replyText
      });
    
    // 图片消息
    case 'image':
      console.log('收到图片消息:', message.PicUrl);
      
      return builder.buildObject({
        ...baseResponse,
        MsgType: 'text',
        Content: '收到图片消息，感谢分享！'
      });
    
    // 语音消息
    case 'voice':
      const recognition = message.Recognition || '（未识别出文字）';
      console.log('收到语音消息，识别结果:', recognition);
      
      return builder.buildObject({
        ...baseResponse,
        MsgType: 'text',
        Content: `语音识别结果：${recognition}`
      });
    
    // 视频消息
    case 'video':
    case 'shortvideo':
      console.log('收到视频消息');
      
      return builder.buildObject({
        ...baseResponse,
        MsgType: 'text',
        Content: '收到视频消息！'
      });
    
    // 位置消息
    case 'location':
      const { Label, Location_X, Location_Y } = message;
      console.log(`位置信息：${Label} (${Location_X}, ${Location_Y})`);
      
      return builder.buildObject({
        ...baseResponse,
        MsgType: 'text',
        Content: `收到位置：${Label}`
      });
    
    // 链接消息
    case 'link':
      console.log('收到链接消息:', message.Title, message.Url);
      
      return builder.buildObject({
        ...baseResponse,
        MsgType: 'text',
        Content: `收到链接：${message.Title}`
      });
    
    // 事件推送
    case 'event':
      return handleEventMessage(message, baseResponse);
    
    // 默认回复
    default:
      console.log('收到未知类型消息:', MsgType);
      
      return builder.buildObject({
        ...baseResponse,
        MsgType: 'text',
        Content: '暂不支持此类型消息'
      });
  }
}

// 解析XML
async function parseXML(xml) {
  return new Promise((resolve, reject) => {
    parser.parseString(xml, (err, result) => {
      if (err) reject(err);
      else resolve(result.xml);
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

const port = process.env.PORT || 80;

async function bootstrap() {
  //await initDB();
  app.listen(port, () => {
    console.log("启动成功", port);
  });
}

bootstrap();
