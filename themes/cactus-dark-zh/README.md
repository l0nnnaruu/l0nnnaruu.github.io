# Cactus Dark

一个给个人网站的响应式、黑色、简单的 [Hexo](http://hexo.io) 主题。

:cactus: [示例](https://probberechts.github.io/cactus-dark/)

![cactus-dark](https://cloud.githubusercontent.com/assets/2175271/19885143/62e9269c-a01d-11e6-8e26-e36a36201d88.png)

## 总览

- [概括](#概括)
- [特性](#特性)
- [安装](#安装)
- [配置](#配置)
- [License](#license)

## 概括

- **版本** : 2.0
- **适配** : Hexo 3 或更高

## 特性

- 完全的响应式
- Disqus
- Googe 分析
- Font Awesome 图标
- 可选的代码高亮方案
- 可配置的导航栏
- 项目列表
- 简洁

## 安装

1. 在 `root` 文件夹中：

    ```git
    $ git clone https://github.com/GroverChouT/cactus-dark-zh.git themes/cactus-dark-zh
    $ npm install hexo-pagination --save
    ```

2. 在 `config.yml` 文件中修改配置 `theme` 如下：

    ```yml
    # theme: landscape
    theme: cactus-dark-zh
    ```

3. 执行：`hexo generate` 和 `hexo server`

## 配置

### 导航

在主题文件夹里的 `_config.yml` 设置：

  ```
  nav:
    首页: /
    关于: /about/
    写作: /archives/
    项目: http://github.com/probberechts
    链接名称: 链接
  ```

### 在首页显示的博客列表

You have two options for the list of blog posts on the home page:

  - Show only the 5 most recent posts (default)

  ```
  customize:
    show_all_posts: false
    post_count: 5
  ```

  - Show all posts 

  ```
  customize:
    show_all_posts: true
  ```

### 项目列表

Create a projects file `source/_data/projects.json`.

  ```json
  [
      {
         "name":"Hexo",
         "url":"https://hexo.io/",
         "desc":"A fast, simple & powerful blog framework"
      },
      {
         "name":"Font Awesome",
         "url":"http://fontawesome.io/",
         "desc":"The iconic font and CSS toolkit"
      }
  ]
  ```

### 社交媒体链接

Cactus Dark can automatically add links to your social media accounts. Therefore, update the theme's `_config.yml`:

  ```
  customize:
    social_links:
      github: your-github-url
      twitter: your-twitter-url
      NAME: your-NAME-url
  ```

where `NAME` is the name of a [Font Awesome icon](http://fontawesome.io/icons/#brand).

### RSS

Set the `rss` field in the theme's `_config.yml` to one of the following values:

1. `rss: false` will totally disable rss (default).
2. `rss: atom.xml` sets a specific feed link.
3. `rss:`leave empty to use the [hexo-generator-feed](https://github.com/hexojs/hexo-generator-feed) plugin. 

### 分析

Add you Google Analytics `tracking_id` to the theme's `_config.yml`.

  ```
  plugins:
      gooogle_analytics: 'UA-49627206-1'            # Format: UA-xxxxxx-xx
  ```

### 评论

First, create a site on Disqus: [https://disqus.com/admin/create/](http://disqus.com/admin/create/).

Next, update the theme's `_config.yml` file:

  ```
  plugins:
      disqus_shortname: SITENAME
  ```

where `SITENAME` is the name you gave your site on Disqus.

### 代码高亮

Pick one of [the available colorschemes](https://github.com/probberechts/cactus-dark/tree/master/source/css/_highlight) and add it to the theme's `_config.yml`:

  ```
  customize:
      highlight: COLORSCHEME_NAME
  ```

## License
MIT
