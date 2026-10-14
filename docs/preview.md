# 公开预览与视频

公开预览采用独立的 GitHub Pages 静态托管，只使用仓库中的虚构演示数据，不连接作者的私人网站或模型账户。

## 发布

仓库管理员在 **Settings → Pages → Build and deployment → Source** 选择 **GitHub Actions**，再到 **Actions → Publish public preview → Run workflow** 运行发布。部署成功后，工作流的 `github-pages` 环境会给出实际预览地址。

公开预览已发布，入口如下：

- [进入小院](https://labixy1.github.io/chestnut-courtyard-public/)。
- [电脑端视频](https://labixy1.github.io/chestnut-courtyard-public/assets/demo/videos/index.html?device=desktop)。
- [手机端视频](https://labixy1.github.io/chestnut-courtyard-public/assets/demo/videos/index.html?device=mobile)。
- 产品与技术文档：[文档目录](README.md)。

静态版可浏览公告板、黑板示例、成长田、记忆档案、树洞影像与旅行记录。实时 AI、资讯更新、上传和跨端同步仍需要自行部署 Cloudflare Worker。预览不会把操作请求发送到不存在的 API。

## 本地核验

```bash
python3 scripts/build_cloud.py --mode preview --hosting static
python3 scripts/cloud_privacy_test.py
python3 scripts/pages_preview_test.py
python3 -m http.server 8080 --directory dist
```

浏览器访问 `http://localhost:8080/`。Pages 使用子目录部署，页面导航、图片与视频均使用相对路径；不需要额外的后端或付费模型调用。
