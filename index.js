const path = require("path");
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const { init: initDB, Counter } = require("./db");

const logger = morgan("tiny");

const app = express();

const crypto = require('crypto');

// 你的微信Token（在微信后台配置的）
const WECHAT_TOKEN = '6tdf';

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cors());
app.use(logger);

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

// 更新计数
app.post("/api/count", async (req, res) => {
  const { action } = req.body;
  if (action === "inc") {
    await Counter.create();
  } else if (action === "clear") {
    await Counter.destroy({
      truncate: true,
    });
  }
  res.send({
    code: 0,
    data: await Counter.count(),
  });
});

// 获取计数
app.get("/api/count", async (req, res) => {
  const result = await Counter.count();
  res.send({
    code: 0,
    data: result,
  });
});

// 小程序调用，获取微信 Open ID
app.get("/api/wx_openid", async (req, res) => {
  if (req.headers["x-wx-source"]) {
    res.send(req.headers["x-wx-openid"]);
  }
});

const port = process.env.PORT || 80;

async function bootstrap() {
  await initDB();
  app.listen(port, () => {
    console.log("启动成功", port);
  });
}

bootstrap();
