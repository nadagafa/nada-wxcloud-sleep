// Our official coze sdk for JavaScript [coze-js](https://github.com/coze-dev/coze-js)
import { CozeAPI } from "@coze/api";

const apiClient = new CozeAPI({
  token: "sat_7jW66Qrns7ltfRcVPaAtpxPW7SMADn0920Ybi6vebt7RD2bRW8AWUPaucCmnbnw8",
  baseURL: "https://api.coze.cn",
});
const res = await apiClient.chat.create({
  bot_id: "7598077850608615433",
  user_id: "123456789",
  additional_messages: [
    {
      content: "hello",
      content_type: "text",
      role: "user",
      type: "question",
    },
  ],
  custom_variables: {
    key_2: "",
  },
});
